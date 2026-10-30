//! Finds content hidden from a human reader inside agent-visible text: markup that is never
//! rendered, CSS that hides text, invisible Unicode, document and file-format metadata, and data
//! smuggled in places a viewer does not show. Paragraphs touching such content are marked
//! `hidden`, since text the user cannot see is a common carrier of injected instructions.
//!
//! Only what can be observed in text is detected: the engine receives Hook payloads, not files
//! or disks. Binary formats are examined when they appear base64-encoded in the text (data URIs
//! and long base64 runs).
//!
//! What counts as hidden depends on how a person normally views the content. Invisible
//! characters, data inside binaries and document internals stay hidden wherever they are read
//! ([`Scope::Always`]). Markup comments, CSS and similar source-level constructs are hidden only
//! when the content is rendered for a reader, as fetched web pages and downloaded files are; in
//! a workspace source file the user reads them in an editor ([`Scope::External`]).

use std::{collections::HashMap, ops::Range, sync::LazyLock};

use base64::{
    Engine as _, alphabet,
    engine::{DecodePaddingMode, GeneralPurpose, GeneralPurposeConfig},
};
use regex::Regex;

use crate::origin::Origin;

macro_rules! regex {
    ($pattern:expr) => {{
        static PATTERN: LazyLock<Regex> = LazyLock::new(|| Regex::new($pattern).unwrap());
        &*PATTERN
    }};
}

/// Attribute text shorter than this (`alt="logo"`) is treated as ordinary labelling.
const MIN_ATTRIBUTE_TEXT: usize = 20;
/// Offsets at or beyond this many pixels off screen hide an element.
const OFFSCREEN_PX: f64 = 500.0;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HiddenSpan {
    /// Byte range of the hidden content in the scanned text.
    pub range: Range<usize>,
    /// The rule that found it, such as `html_comment` or `css_display_none`.
    pub rule: &'static str,
    pub scope: Scope,
}

/// Which content a rule applies to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Scope {
    /// Hidden wherever the content is read.
    Always,
    /// Hidden only in [`Origin::External`] content, which a person views rendered.
    External,
}

impl Scope {
    pub fn applies_to(self, origin: Origin) -> bool {
        self == Self::Always || origin == Origin::External
    }
}

/// Rules for source-level constructs that a person reading the source sees.
const RENDERED_ONLY_PREFIXES: &[&str] = &["html_", "css_", "svg_", "vba_"];

fn scope(rule: &str) -> Scope {
    if RENDERED_ONLY_PREFIXES
        .iter()
        .any(|prefix| rule.starts_with(prefix))
    {
        Scope::External
    } else {
        Scope::Always
    }
}

/// Every hidden region of `text`, ordered by position.
pub fn hidden_spans(text: &str) -> Vec<HiddenSpan> {
    let mut spans = Spans::default();
    let lower = text.to_ascii_lowercase();
    html(text, &lower, &mut spans);
    css(text, &lower, &mut spans);
    unicode(text, &mut spans);
    graphics_and_documents(text, &lower, &mut spans);
    embedded_binaries(text, &mut spans);
    file_systems(text, &mut spans);
    networks(text, &mut spans);
    let mut spans = spans.0;
    spans.sort_by_key(|span| (span.range.start, span.range.end));
    spans.dedup();
    spans
}

#[derive(Default)]
struct Spans(Vec<HiddenSpan>);

impl Spans {
    fn add(&mut self, range: Range<usize>, rule: &'static str) {
        if !range.is_empty() {
            self.0.push(HiddenSpan {
                range,
                rule,
                scope: scope(rule),
            });
        }
    }
}

// ---------------------------------------------------------------------------------------------
// 1. HTML tags and attributes

const NON_RENDERED: &[&str] = &["template", "noscript", "datalist", "noembed", "noframes"];
const TEXT_ATTRIBUTES: &[&str] = &["alt", "aria-label", "aria-describedby", "title"];
const VOID_ELEMENTS: &[&str] = &[
    "area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "source", "track",
    "wbr",
];

fn html(text: &str, lower: &str, spans: &mut Spans) {
    let open_tag = regex!(r"(?s)<([a-zA-Z][a-zA-Z0-9:-]*)\b([^<>]*)>");
    let comment = regex!(r"(?s)<!--.*?(?:-->|\z)");
    let attribute = regex!(r#"(?is)(?:^|\s)([a-z][a-z0-9:_-]*)\s*=\s*(?:"([^"]*)"|'([^']*)')"#);
    let hidden_attribute = regex!(r#"(?i)(?:^|\s)hidden(?:\s|=|/|$)"#);
    let hidden_input = regex!(r#"(?i)\btype\s*=\s*["']?hidden\b"#);
    let ld_json = regex!(r#"(?i)\btype\s*=\s*["']?application/ld\+json\b"#);
    let zero_size = regex!(r#"(?i)\b(?:width|height)\s*=\s*["']?0(?:px)?["']?(?:\s|/|$)"#);

    for found in comment.find_iter(text) {
        spans.add(found.range(), "html_comment");
    }
    let mut ends = ElementEnds::default();
    for captures in open_tag.captures_iter(text) {
        let tag = captures.get(0).expect("match");
        let name = captures[1].to_ascii_lowercase();
        let attributes = &captures[2];
        let mut element = || ends.element(lower, &name, tag.start(), tag.end());

        if NON_RENDERED.contains(&name.as_str()) {
            spans.add(element(), "html_non_rendered");
        }
        if name == "input" && hidden_input.is_match(attributes) {
            spans.add(tag.range(), "html_hidden_input");
        } else if hidden_attribute.is_match(attributes) {
            spans.add(element(), "html_hidden_attribute");
        }
        if name == "meta" {
            spans.add(tag.range(), "html_metadata");
        }
        if name == "script" && ld_json.is_match(attributes) {
            spans.add(element(), "html_metadata");
        }
        if name == "iframe"
            && (zero_size.is_match(attributes) || hidden_attribute.is_match(attributes))
        {
            spans.add(element(), "html_hidden_iframe");
        }
        let attributes_start = captures.get(2).expect("attributes").start();
        for attribute in attribute.captures_iter(attributes) {
            let name = attribute[1].to_ascii_lowercase();
            let value = attribute
                .get(2)
                .or_else(|| attribute.get(3))
                .expect("value");
            if value.as_str().trim().chars().count() < MIN_ATTRIBUTE_TEXT {
                continue;
            }
            let range = attributes_start + value.start()..attributes_start + value.end();
            if TEXT_ATTRIBUTES.contains(&name.as_str()) {
                spans.add(range, "html_alt_text");
            } else if name.starts_with("data-") {
                spans.add(range, "html_data_attribute");
            }
        }
    }
}

/// Finds where elements end, caching one closing-tag pattern per element name.
#[derive(Default)]
struct ElementEnds(HashMap<String, Regex>);

impl ElementEnds {
    /// The byte range of the element opened by the tag at `start..open_end`, including its
    /// matching closing tag, or the tag alone for void, self-closing or unclosed elements.
    fn element(&mut self, lower: &str, name: &str, start: usize, open_end: usize) -> Range<usize> {
        if VOID_ELEMENTS.contains(&name) || lower[..open_end].ends_with("/>") {
            return start..open_end;
        }
        let pattern = self.0.entry(name.to_owned()).or_insert_with(|| {
            Regex::new(&format!(r"<(/?){}(?:\s[^<>]*)?(/?)>", regex::escape(name)))
                .expect("escaped tag name")
        });
        let mut depth = 1_usize;
        for tag in pattern.captures_iter(&lower[open_end..]) {
            if !tag[1].is_empty() {
                depth -= 1;
                if depth == 0 {
                    return start..open_end + tag.get(0).expect("match").end();
                }
            } else if tag[2].is_empty() {
                depth += 1;
            }
        }
        start..open_end
    }
}

// ---------------------------------------------------------------------------------------------
// 2. CSS visual disguise

fn css(text: &str, lower: &str, spans: &mut Spans) {
    let style_block = regex!(r"(?is)<style\b[^>]*>(.*?)(?:</style\s*>|\z)");
    let font_face = regex!(r"(?is)@font-face\s*\{([^{}]*)\}");
    let rule = regex!(r"(?s)([^{}@;]+)\{([^{}]*)\}");
    let selector_name = regex!(r"([.#])([A-Za-z0-9_-]+)\s*$");
    let open_tag = regex!(r"(?s)<([a-zA-Z][a-zA-Z0-9:-]*)\b([^<>]*)>");
    let style_attribute = regex!(r#"(?is)\bstyle\s*=\s*(?:"([^"]*)"|'([^']*)')"#);
    let class_attribute = regex!(r#"(?is)\bclass\s*=\s*(?:"([^"]*)"|'([^']*)')"#);
    let id_attribute = regex!(r#"(?is)\bid\s*=\s*(?:"([^"]*)"|'([^']*)')"#);

    // Fonts embedded as data URIs can map every glyph to a blank shape.
    let mut blank_fonts = Vec::new();
    for block in style_block.captures_iter(text) {
        for face in font_face.captures_iter(&block[1]) {
            let declarations = declarations(&face[1]);
            let embedded = declarations
                .get("src")
                .is_some_and(|src| src.contains("data:"));
            if let (true, Some(family)) = (embedded, declarations.get("font-family")) {
                blank_fonts.push(family.trim_matches(['"', '\'']).to_owned());
            }
        }
    }

    let mut hidden_classes: HashMap<String, &'static str> = HashMap::new();
    let mut hidden_ids: HashMap<String, &'static str> = HashMap::new();
    for block in style_block.captures_iter(text) {
        let css = font_face.replace_all(&block[1], "");
        for found in rule.captures_iter(&css) {
            let Some(hiding) = hiding_rule(&found[2], &blank_fonts) else {
                continue;
            };
            for selector in found[1].split(',') {
                if let Some(name) = selector_name.captures(selector.trim()) {
                    let target = if &name[1] == "." {
                        &mut hidden_classes
                    } else {
                        &mut hidden_ids
                    };
                    target.insert(name[2].to_owned(), hiding);
                }
            }
        }
    }

    let mut ends = ElementEnds::default();
    for captures in open_tag.captures_iter(text) {
        let tag = captures.get(0).expect("match");
        let name = captures[1].to_ascii_lowercase();
        let attributes = &captures[2];
        let mut rules = Vec::new();
        if let Some(style) = style_attribute.captures(attributes) {
            let style = style.get(1).or_else(|| style.get(2)).expect("value");
            rules.extend(hiding_rule(style.as_str(), &blank_fonts));
        }
        if let Some(classes) = class_attribute.captures(attributes) {
            let classes = classes.get(1).or_else(|| classes.get(2)).expect("value");
            rules.extend(
                classes
                    .as_str()
                    .split_whitespace()
                    .filter_map(|class| hidden_classes.get(class).copied()),
            );
        }
        if let Some(id) = id_attribute.captures(attributes) {
            let id = id.get(1).or_else(|| id.get(2)).expect("value");
            rules.extend(hidden_ids.get(id.as_str().trim()).copied());
        }
        if !rules.is_empty() {
            let element = ends.element(lower, &name, tag.start(), tag.end());
            for rule in rules {
                spans.add(element.clone(), rule);
            }
        }
    }
}

/// Lower-cased `property: value` pairs of a declaration block.
fn declarations(block: &str) -> HashMap<String, String> {
    block
        .split(';')
        .filter_map(|declaration| declaration.split_once(':'))
        .map(|(property, value)| {
            (
                property.trim().to_ascii_lowercase(),
                value
                    .trim()
                    .trim_end_matches("!important")
                    .trim()
                    .to_ascii_lowercase(),
            )
        })
        .collect()
}

/// The CSS rule hiding an element styled with `block`, if any.
fn hiding_rule(block: &str, blank_fonts: &[String]) -> Option<&'static str> {
    let style = declarations(block);
    let get = |property: &str| style.get(property).map(String::as_str);

    if get("display") == Some("none")
        || matches!(get("visibility"), Some("hidden" | "collapse"))
        || get("content-visibility") == Some("hidden")
    {
        return Some("css_display_none");
    }
    if get("opacity")
        .and_then(number)
        .is_some_and(|opacity| opacity == 0.0)
        || get("filter")
            .is_some_and(|filter| regex!(r"opacity\(\s*0(?:\.0*)?%?\s*\)").is_match(filter))
        || get("color").is_some_and(transparent_color)
    {
        return Some("css_transparent");
    }
    if let Some(color) = get("color") {
        let background = get("background-color").or_else(|| get("background"));
        let same = match background {
            Some(background) => normalize_color(background) == normalize_color(color),
            None => normalize_color(color).as_deref() == Some("#ffffff"),
        };
        if same && normalize_color(color).is_some() {
            return Some("css_same_color");
        }
    }
    if get("font-size").is_some_and(tiny_font) || get("line-height").and_then(number) == Some(0.0) {
        return Some("css_tiny_font");
    }
    let far_off = |property: &str| {
        get(property)
            .and_then(pixels)
            .is_some_and(|offset| offset <= -OFFSCREEN_PX)
    };
    let positioned = matches!(get("position"), Some("absolute" | "fixed"));
    if (positioned && ["left", "top", "right", "bottom"].into_iter().any(far_off))
        || far_off("text-indent")
        || far_off("margin-left")
        || far_off("margin-top")
    {
        return Some("css_offscreen");
    }
    let zero = |property: &str| get(property).and_then(pixels) == Some(0.0);
    let clipped_overflow = matches!(get("overflow"), Some("hidden" | "clip"));
    if clipped_overflow
        && (zero("height") || zero("max-height") || zero("width") || zero("max-width"))
    {
        return Some("css_zero_box");
    }
    if get("clip").is_some_and(|clip| {
        regex!(r"rect\(\s*0(?:px)?\s*,?\s*0(?:px)?\s*,?\s*0(?:px)?\s*,?\s*0(?:px)?\s*\)")
            .is_match(clip)
    }) || get("clip-path")
        .is_some_and(|clip| regex!(r"inset\(\s*(?:[5-9][0-9]|100)%|circle\(\s*0").is_match(clip))
    {
        return Some("css_clipped");
    }
    if get("z-index")
        .and_then(number)
        .is_some_and(|z_index| z_index <= -100.0)
    {
        return Some("css_behind");
    }
    if get("transform").is_some_and(|transform| {
        regex!(r"scale[xy]?\(\s*0(?:\.0*)?\s*(?:[,)])").is_match(transform)
    }) {
        return Some("css_scaled_zero");
    }
    if get("font-family").is_some_and(|family| {
        blank_fonts
            .iter()
            .any(|font| family.contains(&font.to_ascii_lowercase()))
    }) {
        return Some("css_blank_font");
    }
    None
}

fn number(value: &str) -> Option<f64> {
    let value = value.trim();
    let end = value
        .find(|c: char| !(c.is_ascii_digit() || c == '.' || c == '-' || c == '+'))
        .unwrap_or(value.len());
    value[..end].parse().ok()
}

fn pixels(value: &str) -> Option<f64> {
    let amount = number(value)?;
    let unit = value
        .trim()
        .trim_start_matches(|c: char| c.is_ascii_digit() || c == '.' || c == '-' || c == '+');
    match unit.trim() {
        "" | "px" => Some(amount),
        "em" | "rem" => Some(amount * 16.0),
        "pt" => Some(amount * 4.0 / 3.0),
        "vw" | "vh" | "%" => Some(amount * 10.0),
        _ => None,
    }
}

fn tiny_font(value: &str) -> bool {
    pixels(value).is_some_and(|size| size < 1.0)
}

fn transparent_color(value: &str) -> bool {
    value == "transparent"
        || regex!(r"^(?:rgba|hsla)\(.*,\s*0(?:\.0*)?%?\s*\)$").is_match(value)
        || regex!(r"^(?:rgb|hsl)\([^/]*/\s*0(?:\.0*)?%?\s*\)$").is_match(value)
        || regex!(r"^#(?:[0-9a-f]{6}00|[0-9a-f]{3}0)$").is_match(value)
}

/// `#rrggbb` for hex, `rgb()` and a few named colors.
fn normalize_color(value: &str) -> Option<String> {
    let value = value.trim();
    let named = match value {
        "white" => Some("#ffffff"),
        "black" => Some("#000000"),
        _ => None,
    };
    if let Some(named) = named {
        return Some(named.to_owned());
    }
    if let Some(hex) = value.strip_prefix('#') {
        return match hex.len() {
            3 => Some(format!(
                "#{}",
                hex.chars().flat_map(|c| [c, c]).collect::<String>()
            )),
            6 => Some(format!("#{hex}")),
            _ => None,
        };
    }
    let rgb = regex!(r"^rgba?\(\s*(\d{1,3})\s*,?\s*(\d{1,3})\s*,?\s*(\d{1,3})");
    let captures = rgb.captures(value)?;
    let channel = |index: usize| captures[index].parse::<u8>().ok();
    Some(format!(
        "#{:02x}{:02x}{:02x}",
        channel(1)?,
        channel(2)?,
        channel(3)?
    ))
}

// ---------------------------------------------------------------------------------------------
// 3. Character encoding

fn unicode(text: &str, spans: &mut Spans) {
    let mut run: Option<(usize, &'static str, usize)> = None;
    let flush = |run: &mut Option<(usize, &'static str, usize)>, end: usize, spans: &mut Spans| {
        if let Some((start, rule, count)) = run.take() {
            // A lone zero-width joiner or variation selector is ordinary emoji and script use.
            let minimum = match rule {
                "unicode_variation_selector" | "unicode_joiner" => 2,
                _ => 1,
            };
            if count >= minimum {
                let rule = if rule == "unicode_joiner" {
                    "unicode_invisible"
                } else {
                    rule
                };
                spans.add(start..end, rule);
            }
        }
    };
    let mut end = 0;
    for (position, character) in text.char_indices() {
        let rule = invisible_rule(character);
        match (&mut run, rule) {
            (Some((_, current, count)), Some(rule)) if *current == rule => *count += 1,
            (_, Some(rule)) => {
                flush(&mut run, position, spans);
                run = Some((position, rule, 1));
            }
            (_, None) => flush(&mut run, position, spans),
        }
        end = position + character.len_utf8();
    }
    flush(&mut run, end, spans);
}

fn invisible_rule(character: char) -> Option<&'static str> {
    match character {
        '\u{E0000}'..='\u{E007F}' => Some("unicode_tag"),
        '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}' => Some("unicode_bidi_control"),
        '\u{FE00}'..='\u{FE0F}' | '\u{E0100}'..='\u{E01EF}' => Some("unicode_variation_selector"),
        '\u{200C}' | '\u{200D}' => Some("unicode_joiner"),
        '\u{200B}'
        | '\u{2060}'..='\u{2064}'
        | '\u{FEFF}'
        | '\u{180E}'
        | '\u{115F}'
        | '\u{1160}'
        | '\u{3164}'
        | '\u{FFA0}' => Some("unicode_invisible"),
        '\u{0}' => Some("nul_char"),
        _ => None,
    }
}

// ---------------------------------------------------------------------------------------------
// 4–5. Graphics, media metadata and document internals shown as text

fn graphics_and_documents(text: &str, lower: &str, spans: &mut Spans) {
    let mut ends = ElementEnds::default();

    let svg = regex!(r"(?i)<svg\b[^<>]*>");
    let svg_hidden = regex!(r"(?i)<(desc|title|metadata|defs)\b[^<>]*>");
    for open in svg.find_iter(text) {
        let element = ends.element(lower, "svg", open.start(), open.end());
        for inner in svg_hidden.captures_iter(&text[element.clone()]) {
            let tag = inner.get(0).expect("match");
            let name = inner[1].to_ascii_lowercase();
            let start = element.start + tag.start();
            spans.add(
                ends.element(lower, &name, start, element.start + tag.end()),
                "svg_metadata",
            );
        }
    }

    let xmp = regex!(
        r"(?is)<\?xpacket\s+begin.*?(?:<\?xpacket\s+end[^>]*>|\z)|<x:xmpmeta\b.*?(?:</x:xmpmeta>|\z)"
    );
    // exiftool prints `Field Name<padding> : value`.
    let exif = regex!(
        r"(?m)^(?:Image Description|User Comment|XP Comment|XP Subject|XP Title|XP Keywords|Comment|Caption-Abstract|Special Instructions|Description|Artist|Copyright Notice|Creator)\s{2,}:\s+\S.*$"
    );
    for found in xmp.find_iter(text).chain(exif.find_iter(text)) {
        spans.add(found.range(), "image_metadata");
    }

    pdf(text, spans);

    let run = regex!(r"<w:r\b[^<>]*>");
    let vanish = regex!(r#"<w:(?:vanish|webHidden)(?:\s+w:val\s*=\s*"(?:true|1|on)")?\s*/>"#);
    for open in run.find_iter(text) {
        let element = ends.element(lower, "w:r", open.start(), open.end());
        if vanish.is_match(&text[element.clone()]) {
            spans.add(element, "office_hidden_text");
        }
    }
    let notes = regex!(r"<p:notes\b[^<>]*>");
    for open in notes.find_iter(text) {
        spans.add(
            ends.element(lower, "p:notes", open.start(), open.end()),
            "office_slide_notes",
        );
    }
    let hidden_sheet =
        regex!(r#"(?i)<sheet\b[^<>]*\bstate\s*=\s*["'](?:hidden|veryhidden)["'][^<>]*>"#);
    for found in hidden_sheet.find_iter(text) {
        spans.add(found.range(), "xlsx_hidden_sheet");
    }

    let vba_source =
        regex!(r"(?im)^\s*(?:Attribute VB_Name\b|(?:Private |Public )?(?:Sub|Function) \w+\s*\()");
    if vba_source.is_match(text) {
        let comment = regex!(r"(?im)^[ \t]*(?:'|Rem\b).*$");
        let hidden_control = regex!(r"(?im)^.*\.Visible\s*=\s*(?:False|0)\b.*$");
        for found in comment.find_iter(text) {
            spans.add(found.range(), "vba_comment");
        }
        for found in hidden_control.find_iter(text) {
            spans.add(found.range(), "vba_hidden_control");
        }
    }
}

fn pdf(text: &str, spans: &mut Spans) {
    let text_object = regex!(r"(?s)\bBT\b.*?\bET\b");
    let invisible = regex!(r"\b3\s+Tr\b");
    let white_fill = regex!(
        r"\b(?:1(?:\.0*)?\s+1(?:\.0*)?\s+1(?:\.0*)?\s+rg|1(?:\.0*)?\s+g|0\s+0\s+0\s+0\s+k)\b"
    );
    for found in text_object.find_iter(text) {
        if invisible.is_match(found.as_str()) {
            spans.add(found.range(), "pdf_invisible_text");
        } else if white_fill.is_match(found.as_str()) {
            spans.add(found.range(), "pdf_white_text");
        }
    }

    if !text.contains("%PDF-") {
        return;
    }
    let object = regex!(r"(?ms)^(\d+)\s+(\d+)\s+obj\b.*?\bendobj\b");
    let reference = regex!(r"\b(\d+)\s+\d+\s+R\b");
    let objects: Vec<(u64, Range<usize>)> = object
        .captures_iter(text)
        .filter_map(|captures| {
            Some((
                captures[1].parse().ok()?,
                captures.get(0).expect("match").range(),
            ))
        })
        .collect();
    let mut last_definition = HashMap::new();
    for (number, range) in &objects {
        last_definition.insert(*number, range.start);
    }
    // Where each object is referenced, to tell references from other objects apart from an
    // object's references to itself.
    let mut references: HashMap<u64, Vec<usize>> = HashMap::new();
    for captures in reference.captures_iter(text) {
        if let Ok(number) = captures[1].parse() {
            references
                .entry(number)
                .or_default()
                .push(captures.get(0).expect("match").start());
        }
    }
    let root = regex!(r"/Type\s*/(?:Catalog|XRef|ObjStm)\b");
    for (number, range) in &objects {
        // An incremental update redefines the object; the earlier version is no longer shown.
        if last_definition[number] != range.start {
            spans.add(range.clone(), "pdf_superseded_object");
            continue;
        }
        let referenced = references
            .get(number)
            .is_some_and(|positions| positions.iter().any(|position| !range.contains(position)));
        if !referenced && !root.is_match(&text[range.clone()]) {
            spans.add(range.clone(), "pdf_orphan_object");
        }
    }
}

// ---------------------------------------------------------------------------------------------
// 6. Binary formats embedded as base64

static BASE64: LazyLock<GeneralPurpose> = LazyLock::new(|| {
    GeneralPurpose::new(
        &alphabet::STANDARD,
        GeneralPurposeConfig::new().with_decode_padding_mode(DecodePaddingMode::Indifferent),
    )
});

fn embedded_binaries(text: &str, spans: &mut Spans) {
    let data_uri = regex!(r"data:[\w/+.-]*;base64,([A-Za-z0-9+/]{16,}={0,2})");
    let long_run = regex!(r"[A-Za-z0-9+/]{512,}={0,2}");
    let mut seen = Vec::new();
    for found in data_uri
        .captures_iter(text)
        .filter_map(|captures| captures.get(1))
        .chain(long_run.find_iter(text))
    {
        if seen
            .iter()
            .any(|range: &Range<usize>| range.contains(&found.start()))
        {
            continue;
        }
        seen.push(found.range());
        let Ok(bytes) = BASE64.decode(found.as_str()) else {
            continue;
        };
        for rule in binary_rules(&bytes) {
            spans.add(found.range(), rule);
        }
    }
}

/// Hidden-data findings in a decoded file.
fn binary_rules(bytes: &[u8]) -> Vec<&'static str> {
    let mut rules = Vec::new();
    let format = if bytes.starts_with(b"\x89PNG\r\n\x1a\n") {
        let (text_chunk, trailing) = png(bytes);
        if text_chunk {
            rules.push("embedded_text_chunk");
        }
        if trailing {
            rules.push("embedded_trailing_data");
        }
        Some("png")
    } else if bytes.starts_with(&[0xFF, 0xD8, 0xFF]) {
        let (comment, trailing) = jpeg(bytes);
        if comment {
            rules.push("embedded_text_chunk");
        }
        if trailing {
            rules.push("embedded_trailing_data");
        }
        Some("jpeg")
    } else if bytes.starts_with(b"%PDF-") {
        let end = find_last(bytes, b"%%EOF").map_or(bytes.len(), |end| end + 5);
        if bytes[end..].iter().any(|byte| !byte.is_ascii_whitespace()) {
            rules.push("embedded_trailing_data");
        }
        Some("pdf")
    } else if bytes.starts_with(b"PK\x03\x04") {
        Some("zip")
    } else if bytes.starts_with(b"GIF8") {
        Some("gif")
    } else {
        None
    };
    if let Some(eocd) = find_last(bytes, b"PK\x05\x06") {
        let comment_length = bytes
            .get(eocd + 20..eocd + 22)
            .map_or(0, |length| u16::from_le_bytes([length[0], length[1]]));
        if comment_length > 0 {
            rules.push("embedded_zip_comment");
        }
        if format.is_some_and(|format| format != "zip") {
            rules.push("embedded_polyglot");
        }
    }
    if format.is_some_and(|format| format != "pdf")
        && find(&bytes[..bytes.len().min(1024)], b"%PDF-").is_some()
    {
        rules.push("embedded_polyglot");
    }
    rules.dedup();
    rules
}

/// Whether a PNG has text chunks and whether bytes follow its IEND chunk.
fn png(bytes: &[u8]) -> (bool, bool) {
    let mut offset = 8;
    let mut text_chunk = false;
    while let Some(header) = bytes.get(offset..offset + 8) {
        let length = u32::from_be_bytes([header[0], header[1], header[2], header[3]]) as usize;
        let kind = &header[4..8];
        if matches!(kind, b"tEXt" | b"zTXt" | b"iTXt") {
            text_chunk = true;
        }
        offset += 12 + length;
        if kind == b"IEND" {
            return (text_chunk, offset < bytes.len());
        }
    }
    (text_chunk, false)
}

/// Whether a JPEG has comment segments and whether bytes follow its end-of-image marker.
fn jpeg(bytes: &[u8]) -> (bool, bool) {
    let mut offset = 2;
    let mut comment = false;
    while let Some(&[0xFF, marker]) = bytes.get(offset..offset + 2) {
        if marker == 0xFE {
            comment = true;
        }
        if marker == 0xDA {
            break;
        }
        let Some(length) = bytes.get(offset + 2..offset + 4) else {
            return (comment, false);
        };
        offset += 2 + u16::from_be_bytes([length[0], length[1]]) as usize;
    }
    // Entropy-coded data escapes 0xFF as 0xFF00, so the first 0xFFD9 ends the image.
    let end = (offset..bytes.len().saturating_sub(1))
        .find(|&index| bytes[index] == 0xFF && bytes[index + 1] == 0xD9)
        .map(|index| index + 2);
    (comment, end.is_some_and(|end| end < bytes.len()))
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

fn find_last(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .rposition(|window| window == needle)
}

// ---------------------------------------------------------------------------------------------
// 7. File systems

fn file_systems(text: &str, spans: &mut Spans) {
    // `dir /r` lists `name:stream:$DATA`; `Get-Content -Stream name`; `normal.txt:secret.txt`.
    let ads = regex!(
        r"(?i)\S+:\$DATA\b|-Stream\s+\S+|\b[\w.-]+\.[A-Za-z0-9]{1,8}:[\w-]*[A-Za-z][\w-]*\.[A-Za-z0-9]{1,8}\b"
    );
    for found in ads.find_iter(text) {
        if !text[..found.start()].ends_with('/') {
            spans.add(found.range(), "ntfs_ads");
        }
    }
    // `getfattr -d` and `xattr -l` output.
    let xattr =
        regex!(r#"(?m)^[ \t]*(?:(?:user|trusted|security)\.[\w.-]+="|com\.apple\.[\w.-]+:).*$"#);
    for found in xattr.find_iter(text) {
        spans.add(found.range(), "xattr");
    }
    let fork = regex!(r"\S*\.\.namedfork/rsrc\b|(?:^|/)\._[^/\s]+");
    for found in fork.find_iter(text) {
        spans.add(found.range(), "resource_fork");
    }
}

// ---------------------------------------------------------------------------------------------
// 8. Network covert channels

fn networks(text: &str, spans: &mut Spans) {
    let domain = regex!(
        r"\b([A-Za-z0-9_-]{32,63})\.(?:[A-Za-z0-9-]{1,63}\.)*[A-Za-z0-9-]{1,63}\.[A-Za-z]{2,24}\b"
    );
    for captures in domain.captures_iter(text) {
        if encoded_label(&captures[1]) {
            spans.add(captures.get(0).expect("match").range(), "dns_tunnel");
        }
    }
    let txt = regex!(r#"(?i)\bTXT\s+"([A-Za-z0-9+/]{64,}={0,2})""#);
    for captures in txt.captures_iter(text) {
        spans.add(captures.get(0).expect("match").range(), "dns_tunnel");
    }
}

/// A DNS label that carries encoded data rather than a name: hex, base32 or base64url.
fn encoded_label(label: &str) -> bool {
    let hex = label.bytes().all(|byte| byte.is_ascii_hexdigit());
    let base32 = label
        .bytes()
        .all(|byte| byte.is_ascii_alphabetic() || (b'2'..=b'7').contains(&byte));
    let digits = label.bytes().filter(u8::is_ascii_digit).count();
    let mixed_case = label.bytes().any(|byte| byte.is_ascii_uppercase())
        && label.bytes().any(|byte| byte.is_ascii_lowercase());
    hex || (base32 && digits >= 4) || (mixed_case && digits >= 4)
}
