// The graph canvas. Rust sends what to draw and what to pick out; this paints it with
// Cytoscape and sends back what was clicked. Colors are CSS variables, read when painting, so
// the canvas follows the light or dark theme.
const css = name => getComputedStyle(document.documentElement).getPropertyValue(name).trim();
const color = key => el => css(el.data(key));

const style = () => [
  { selector: 'node', style: {
    shape: 'round-rectangle', width: 172, height: 36, 'background-color': color('fill'), 'background-opacity': 1,
    'border-color': color('border'), 'border-width': 'data(borderWidth)', label: 'data(label)',
    'text-valign': 'center', 'text-halign': 'center', 'text-wrap': 'ellipsis', 'text-max-width': 160,
    'font-size': 11, color: css('--text'),
  }},
  { selector: 'node[?soft]', style: { 'background-opacity': 0.14, 'corner-radius': 18 } },
  { selector: 'node[?area]', style: {
    'background-color': css('--group-bg'), 'border-color': css('--group-border'), 'border-width': 1,
    'text-valign': 'top', 'font-size': 12, 'font-weight': 700, color: css('--muted'), padding: 18, 'text-margin-y': -6,
  }},
  { selector: 'edge', style: {
    width: 1.3, 'line-color': css('--flow'), 'target-arrow-color': css('--flow'), 'target-arrow-shape': 'triangle',
    'arrow-scale': 0.7, 'curve-style': 'bezier',
  }},
  { selector: 'edge[?cause]', style: {
    width: 2, 'line-style': 'dashed', 'line-color': css('--cause'), 'target-arrow-color': css('--cause'),
    'curve-style': 'unbundled-bezier', 'control-point-distances': 40, label: 'data(label)', 'font-size': 10,
    'font-weight': 700, color: css('--cause'), 'text-background-color': css('--bg'), 'text-background-opacity': 1,
    'text-background-padding': 2, 'text-background-shape': 'round-rectangle',
  }},
  { selector: '.faded', style: { opacity: 0.12 } },
  { selector: 'node.chain', style: { 'border-color': css('--deny'), 'border-width': 4 } },
  { selector: 'edge.chain', style: {
    width: 3.2, 'line-style': 'solid', 'line-color': css('--deny'), 'target-arrow-color': css('--deny'), opacity: 1 } },
  { selector: ':selected', style: { 'overlay-color': css('--accent'), 'overlay-opacity': 0.18, 'overlay-padding': 5 } },
];

const container = await new Promise(resolve => {
  const find = () => { const el = document.getElementById('graph-canvas'); el ? resolve(el) : requestAnimationFrame(find); };
  find();
});
let cy = null;
new ResizeObserver(() => cy?.resize()).observe(container);
matchMedia('(prefers-color-scheme: dark)').addEventListener('change', () => cy?.style(style()));

function highlight(h) {
  if (!cy) return;
  cy.elements().removeClass('faded chain');
  cy.$(':selected').unselect();
  if (!h) return;
  cy.$id(h.select).select();
  if (!h.edges.length) return;
  let chain = cy.collection();
  for (const id of [...h.nodes, ...h.edges]) chain = chain.union(cy.$id(id));
  chain.addClass('chain');
  cy.elements().not(chain).not('node[?area]').addClass('faded');
}

function render({ elements, keepView, highlight: h }) {
  const saved = keepView && cy ? { zoom: cy.zoom(), pan: cy.pan() } : null;
  cy?.destroy();
  cy = cytoscape({ container, elements, style: style(), layout: { name: 'preset' },
    wheelSensitivity: 0.25, minZoom: 0.05, maxZoom: 3, boxSelectionEnabled: false });
  if (saved) { cy.zoom(saved.zoom); cy.pan(saved.pan); } else cy.fit(undefined, 40);
  highlight(h);
  cy.on('tap', 'node[seq]', e => dioxus.send({ type: 'node', seq: e.target.data('seq') }));
  cy.on('tap', 'edge[?cause]', e => dioxus.send({ type: 'edge', call: e.target.data('call'), to: e.target.data('to'), id: e.target.id() }));
  cy.on('tap', e => { if (e.target === cy) dioxus.send({ type: 'blank' }); });
}

while (true) {
  const command = await dioxus.recv();
  if (command.type === 'render') render(command);
  else if (command.type === 'highlight') highlight(command.highlight);
  else if (command.type === 'fit') cy?.fit(undefined, 40);
  else if (command.type === 'clear') { cy?.destroy(); cy = null; }
  else if (command.type === 'focus' && cy) {
    const node = cy.$id(command.id);
    if (node.length) cy.animate({ center: { eles: node }, zoom: Math.max(cy.zoom(), 0.9) }, { duration: 250 });
  }
}
