use std::{error::Error, fmt};

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use withhuman_contracts::decisions::{
    CausalCandidate, CausalContext, CausalPath, DecisionRequest, DecisionResponse, ValueMatch,
};

use crate::{
    DecisionConfig,
    path::{ChainNode, build_path},
};

const VERIFY_GRAPH: &str = "\
MATCH (session:Session {session_id: $session_id}) \
MATCH (call:ExecutionNode {session_id: $session_id, seq: $call_seq, type: 'Call'}) \
WHERE session.version >= $graph_version AND call.seq <= $graph_version \
RETURN session.version, call.seq";

const LOAD_CURRENT: &str = "\
MATCH (call:ExecutionNode {session_id:$session_id,seq:$call_seq,type:'Call'})-[:LINK {kind:'member'}]->(sequence:ExecutionNode {type:'Sequence',depth:1}) \
RETURN sequence.sequence, sequence.body, sequence.parent_state, call.body, call.tool_use_id, call.risk";

/// `instructing_pieces(S)` for every listed sequence S: the instructing pieces of the results of
/// S's Calls, reached only through `:LINK` (Message <-follows- Call -result-> result <-part_of-
/// piece). A sequence without a Message reaches its Calls through `member`.
const INSTRUCTING_PIECES: &str = "\
UNWIND $sequences AS number \
MATCH (sequence:ExecutionNode {session_id:$session_id,type:'Sequence',depth:1,sequence:number}) \
OPTIONAL MATCH (message:ExecutionNode {session_id:$session_id,type:'Message',sequence:number}) \
MATCH (call:ExecutionNode {session_id:$session_id,type:'Call'})-[:LINK {kind:'member'}]->(sequence) \
WHERE message IS NULL OR (call)-[:LINK {kind:'follows'}]->(message) \
MATCH (call)-[:LINK {kind:'result'}]->(:ExecutionNode)<-[:LINK {kind:'part_of'}]-(piece:ExecutionNode {depth:3}) \
WHERE piece.hidden = true OR (piece.flagged = true AND (piece.instructs IS NULL OR piece.instructs >= $sentence_from)) \
RETURN DISTINCT number, piece.seq AS piece_seq, piece.text, \
       coalesce(piece.hidden, false) = false AND piece.instructs IS NULL AS pending \
ORDER BY number DESC, piece_seq";

const LOAD_PLANS: &str = "\
MATCH (current:ExecutionNode {session_id:$session_id,type:'Sequence',depth:1,sequence:$sequence}) \
CALL (current) { \
  WITH current MATCH (candidate:ExecutionNode {session_id:$session_id,type:'Sequence',depth:1}) \
  WHERE candidate.sequence < current.sequence AND candidate.sequence >= current.sequence - $seq_window \
    AND coalesce(candidate.agent_id, '') = coalesce(current.agent_id, '') \
  RETURN 's' AS kind, candidate.sequence AS number, candidate.seq AS node_seq, candidate.body AS body, \
         coalesce(candidate.has_message, false) AS has_message \
  UNION \
  WITH current MATCH (candidate:ExecutionNode {session_id:$session_id,type:'Request',depth:1}) \
  WHERE candidate.sequence <= current.sequence \
  WITH candidate ORDER BY candidate.sequence DESC LIMIT $prompt_window \
  RETURN 'r' AS kind, candidate.sequence AS number, candidate.seq AS node_seq, candidate.body AS body, \
         false AS has_message \
  UNION \
  WITH current MATCH (candidate:ExecutionNode {session_id:$session_id,type:'Instruction',depth:1}) \
  WHERE candidate.sequence < current.sequence \
  WITH candidate ORDER BY candidate.sequence DESC, candidate.seq DESC LIMIT 1 \
  RETURN 'i' AS kind, candidate.seq AS number, candidate.seq AS node_seq, candidate.body AS body, \
         false AS has_message \
} RETURN kind, number, node_seq, coalesce(body, ''), has_message \
ORDER BY CASE kind WHEN 's' THEN 0 WHEN 'r' THEN 1 ELSE 2 END, number DESC";

/// The previous N sequences plus every sequence on their `:CAUSE` paths. `{max_hops}` is
/// replaced with `WITHHUMAN_PARENT_MAX_HOPS`.
const LOAD_TEXT_SEQUENCES: &str = "\
MATCH (current:ExecutionNode {session_id:$session_id,type:'Sequence',depth:1,sequence:$sequence}) \
MATCH (previous:ExecutionNode {session_id:$session_id,type:'Sequence',depth:1}) \
WHERE previous.sequence < current.sequence AND previous.sequence >= current.sequence - $seq_window \
  AND coalesce(previous.agent_id, '') = coalesce(current.agent_id, '') \
OPTIONAL MATCH path=(previous)-[:CAUSE*1..{max_hops}]->(ancestor:ExecutionNode {type:'Sequence',depth:1}) \
WHERE all(edge IN relationships(path) WHERE edge.kind = 'parent' AND edge.superseded_at IS NULL) \
WITH current, collect(DISTINCT previous.sequence) + collect(DISTINCT ancestor.sequence) AS numbers \
UNWIND numbers AS number \
WITH DISTINCT current, number WHERE number IS NOT NULL AND number < current.sequence \
RETURN number ORDER BY number DESC";

/// The first node (in commit order) that mentioned a value of the Call's arguments. It is a
/// match only when that node is a piece of an earlier sequence.
const LOAD_VALUE_MATCH: &str = "\
MATCH (call:ExecutionNode {session_id:$session_id,seq:$call_seq})-[:LINK {kind:'mentions_token'}]->(token:Token) \
MATCH (owner:ExecutionNode {session_id:$session_id})-[:LINK {kind:'mentions_token'}]->(:Token {session_id:$session_id,key_kind:token.key_kind,key:token.key}) \
WITH DISTINCT token.key AS value, owner \
ORDER BY coalesce(owner.created_in_seq, owner.seq), owner.depth DESC \
WITH value, head(collect(owner)) AS first \
WHERE first.depth = 3 AND first.sequence < $sequence \
RETURN first.seq, value ORDER BY first.sequence, first.index LIMIT 1";

/// `{max_hops}` is replaced with `WITHHUMAN_PARENT_MAX_HOPS + 2` so a loop is still visible.
const LOAD_CHAIN: &str = "\
MATCH (call:ExecutionNode {session_id:$session_id,seq:$call_seq,type:'Call'})-[:LINK {kind:'member'}]->(start:ExecutionNode {type:'Sequence',depth:1}) \
OPTIONAL MATCH (call)-[direct:LINK {kind:'from_text'}]->(piece:ExecutionNode {depth:3}) \
OPTIONAL MATCH chain=(start)-[:CAUSE*1..{max_hops}]->(:ExecutionNode {depth:1}) \
WHERE all(edge IN relationships(chain) WHERE edge.kind = 'parent' AND edge.superseded_at IS NULL) \
WITH start, piece, direct, chain ORDER BY CASE WHEN chain IS NULL THEN 0 ELSE length(chain) END DESC LIMIT 1 \
WITH piece, direct, \
     CASE WHEN chain IS NULL THEN [start] ELSE nodes(chain) END AS chain_nodes, \
     CASE WHEN chain IS NULL THEN [] ELSE relationships(chain) END AS chain_edges \
RETURN piece.seq, direct.accepted, \
       [node IN chain_nodes | [node.seq, node.type, node.parent_state]], \
       [edge IN chain_edges | edge.accepted]";

const LOAD_CHAIN_FROM_TEXT: &str = "\
UNWIND $node_seqs AS node_seq \
MATCH (sequence:ExecutionNode {session_id:$session_id,seq:node_seq,type:'Sequence'}) \
MATCH (call:ExecutionNode {type:'Call'})-[:LINK {kind:'member'}]->(sequence) \
MATCH (call)-[edge:LINK {kind:'from_text'}]->(piece:ExecutionNode {depth:3}) \
RETURN node_seq, call.seq, piece.seq, edge.accepted ORDER BY node_seq, call.seq";

/// Verdict, parent and from_text are written in one statement, so in one transaction. A
/// sequence whose parent is already `decided` or `none` keeps it unless parents are re-asked per
/// Call, in which case the earlier parent edge gets `superseded_at`.
const WRITE_VERDICT: &str = "\
MATCH (session:Session {session_id: $session_id}) \
MATCH (call:ExecutionNode {session_id: $session_id, seq: $call_seq, type: 'Call'}) \
OPTIONAL MATCH (call)-[:LINK {kind:'member'}]->(sequence:ExecutionNode {type:'Sequence',depth:1}) \
OPTIONAL MATCH (parent_target:ExecutionNode {session_id:$session_id,seq:$parent_target}) \
OPTIONAL MATCH (text_target:ExecutionNode {session_id:$session_id,seq:$text_target,depth:3}) \
MERGE (verdict:Verdict {session_id: $session_id, call_seq: $call_seq}) \
SET verdict.decision = $decision, verdict.reason = $reason, verdict.rule = $rule, \
    verdict.start = $start, verdict.graph_version = $graph_version, \
    verdict.mode = $mode, verdict.jev_json = $jev_json, verdict.updated_at = timestamp(), \
    verdict.seq_window = $seq_window, verdict.prompt_window = $prompt_window, \
    verdict.path_json = $path_json \
SET call.decision = $decision, call.decision_reason = $reason, call.decision_rule = $rule, \
    call.decision_start = $start, call.decision_version = $graph_version \
MERGE (call)-[cause:CAUSE {kind: 'mock'}]->(verdict) \
SET cause.graph_version = $graph_version \
MERGE (call)-[:HAS_VERDICT]->(verdict) \
WITH call, sequence, parent_target, text_target, \
     $parent_state IS NOT NULL AND sequence IS NOT NULL AND \
     ($per_call OR coalesce(sequence.parent_state, 'pending') IN ['pending', 'unresolved']) AS write_parent \
CALL (sequence, write_parent) { \
  WITH sequence, write_parent WHERE write_parent AND $parent_state = 'decided' \
  OPTIONAL MATCH (sequence)-[old:CAUSE {kind:'parent'}]->() WHERE old.superseded_at IS NULL \
  SET old.superseded_at = timestamp() \
  RETURN count(old) AS superseded \
  UNION \
  WITH sequence, write_parent WHERE NOT write_parent OR $parent_state <> 'decided' \
  RETURN 0 AS superseded \
} \
FOREACH (_ IN CASE WHEN write_parent THEN [1] ELSE [] END | \
  SET sequence.parent_state = $parent_state, sequence.parent_seq_window = $seq_window, \
      sequence.parent_prompt_window = $prompt_window, sequence.parent_decided_at = timestamp() \
) \
FOREACH (_ IN CASE WHEN write_parent AND parent_target IS NOT NULL AND $parent_state = 'decided' THEN [1] ELSE [] END | \
  CREATE (sequence)-[parent:CAUSE {kind:'parent'}]->(parent_target) \
  SET parent.probability = $parent_probability, parent.accepted = $parent_accepted, \
      parent.candidates = $parent_candidates, parent.seq_window = $seq_window, \
      parent.prompt_window = $prompt_window, parent.decided_at = timestamp() \
) \
FOREACH (_ IN CASE WHEN $from_text_state IS NOT NULL THEN [1] ELSE [] END | \
  SET call.from_text_state = $from_text_state \
) \
FOREACH (_ IN CASE WHEN text_target IS NOT NULL AND $from_text_state = 'decided' THEN [1] ELSE [] END | \
  MERGE (call)-[source:LINK {kind:'from_text'}]->(text_target) \
  SET source.fact = $from_text_fact, source.basis = $from_text_basis, source.value = $from_text_value, \
      source.probability = $from_text_probability, source.accepted = $from_text_accepted, \
      source.candidates = $from_text_candidates \
) \
RETURN true AS written";

#[async_trait]
pub trait DecisionRepository: Send + Sync + 'static {
    async fn health(&self) -> Result<(), RepositoryError>;
    async fn verify_graph(&self, request: &DecisionRequest) -> Result<(), RepositoryError>;
    async fn prepare_causal(
        &self,
        _request: &DecisionRequest,
    ) -> Result<Option<CausalContext>, RepositoryError> {
        Ok(None)
    }
    async fn persist(
        &self,
        request: &DecisionRequest,
        response: &DecisionResponse,
    ) -> Result<(), RepositoryError>;
    async fn causal_path(
        &self,
        _request: &DecisionRequest,
    ) -> Result<Option<CausalPath>, RepositoryError> {
        Ok(None)
    }
}

#[derive(Clone)]
pub struct Neo4jDecisionRepository {
    endpoint: String,
    user: String,
    password: String,
    client: reqwest::Client,
    seq_window: u64,
    prompt_window: u64,
    max_hops: u64,
    per_call: bool,
    body_chars: usize,
    sentence_from: f64,
}

impl Neo4jDecisionRepository {
    pub async fn connect(config: &DecisionConfig) -> Result<Self, RepositoryError> {
        let repository = Self {
            endpoint: format!(
                "{}/db/{}/query/v2",
                config.neo4j_url.trim_end_matches('/'),
                config.neo4j_database
            ),
            user: config.neo4j_user.clone(),
            password: config.neo4j_password.clone(),
            client: reqwest::Client::new(),
            seq_window: config.parent_seq_window,
            prompt_window: config.parent_prompt_window,
            max_hops: config.parent_max_hops,
            per_call: config.parent_per_call,
            body_chars: config.parent_body_chars,
            sentence_from: config.sentence_from,
        };
        repository.health().await?;
        Ok(repository)
    }

    async fn execute(
        &self,
        statement: &str,
        parameters: Value,
    ) -> Result<QueryData, RepositoryError> {
        let response = self
            .client
            .post(&self.endpoint)
            .basic_auth(&self.user, Some(&self.password))
            .json(&QueryRequest {
                statement,
                parameters,
            })
            .send()
            .await
            .map_err(|error| RepositoryError::Unavailable(error.to_string()))?;
        let status = response.status();
        let body: QueryResponse = response
            .json()
            .await
            .map_err(|error| RepositoryError::InvalidResponse(error.to_string()))?;
        if !status.is_success() {
            return Err(RepositoryError::Unavailable(format!("HTTP {status}")));
        }
        if !body.errors.is_empty() {
            return Err(RepositoryError::Query(
                body.errors
                    .into_iter()
                    .map(|error| format!("{}: {}", error.code, error.message))
                    .collect::<Vec<_>>()
                    .join("; "),
            ));
        }
        body.data
            .ok_or_else(|| RepositoryError::InvalidResponse("missing data".into()))
    }
}

#[async_trait]
impl DecisionRepository for Neo4jDecisionRepository {
    async fn health(&self) -> Result<(), RepositoryError> {
        self.execute("RETURN 1", json!({})).await?;
        Ok(())
    }

    async fn verify_graph(&self, request: &DecisionRequest) -> Result<(), RepositoryError> {
        let data = self
            .execute(
                VERIFY_GRAPH,
                json!({
                    "session_id":request.session_id,
                    "call_seq":request.call_seq,
                    "graph_version":request.graph_version,
                }),
            )
            .await?;
        if data.values.is_empty() {
            return Err(RepositoryError::NotFound);
        }
        Ok(())
    }

    async fn prepare_causal(
        &self,
        request: &DecisionRequest,
    ) -> Result<Option<CausalContext>, RepositoryError> {
        let current = self
            .execute(
                LOAD_CURRENT,
                json!({"session_id":request.session_id,"call_seq":request.call_seq}),
            )
            .await?;
        let Some(row) = current.values.first() else {
            return Ok(None);
        };
        let sequence = unsigned(value_at(row, 0, "sequence")?, "sequence")?;
        let current_body = string_at(row, 1);
        let parent_state = row
            .get(2)
            .and_then(Value::as_str)
            .unwrap_or("pending")
            .to_owned();
        let action = string_at(row, 3);
        let tool_use_id = row.get(4).and_then(Value::as_str).map(str::to_owned);
        let risk = row.get(5).and_then(Value::as_f64);
        let parameters = json!({
            "session_id":request.session_id,"sequence":sequence,
            "seq_window":self.seq_window,"prompt_window":self.prompt_window,
        });

        let plan_rows = self.execute(LOAD_PLANS, parameters.clone()).await?.values;
        let plan_sequences = plan_rows
            .iter()
            .filter(|row| row.first().and_then(Value::as_str) == Some("s"))
            .map(|row| unsigned(value_at(row, 1, "plan_sequence")?, "plan_sequence"))
            .collect::<Result<Vec<_>, _>>()?;
        let plan_pieces = self
            .instructing_pieces(&request.session_id, &plan_sequences)
            .await?;
        let plans = plan_rows
            .iter()
            .map(|row| self.plan_from_row(row, &plan_pieces))
            .collect::<Result<Vec<_>, _>>()?;

        let text_sequences = self
            .execute(
                &LOAD_TEXT_SEQUENCES.replace("{max_hops}", &self.max_hops.to_string()),
                parameters,
            )
            .await?
            .values
            .iter()
            .map(|row| unsigned(value_at(row, 0, "text_sequence")?, "text_sequence"))
            .collect::<Result<Vec<_>, _>>()?;
        let mut texts: Vec<CausalCandidate> = Vec::new();
        for piece in self
            .instructing_pieces(&request.session_id, &text_sequences)
            .await?
        {
            if !texts
                .iter()
                .any(|text| text.node_seq == piece.candidate.node_seq)
            {
                texts.push(piece.candidate);
            }
        }

        let value_data = self
            .execute(
                LOAD_VALUE_MATCH,
                json!({
                    "session_id":request.session_id,"call_seq":request.call_seq,"sequence":sequence,
                }),
            )
            .await?;
        let value_match = value_data
            .values
            .first()
            .map(|row| {
                Ok(ValueMatch {
                    piece_seq: integer(value_at(row, 0, "piece_seq")?, "piece_seq")?,
                    value: string_at(row, 1),
                })
            })
            .transpose()?;
        Ok(Some(CausalContext {
            sequence,
            call_seq: request.call_seq,
            tool_use_id,
            current: current_body,
            action,
            parent_state,
            plans,
            texts,
            value_match,
            seq_window: self.seq_window,
            prompt_window: self.prompt_window,
            risk,
        }))
    }

    async fn persist(
        &self,
        request: &DecisionRequest,
        response: &DecisionResponse,
    ) -> Result<(), RepositoryError> {
        let context = request.causal_context.as_ref();
        let causal = response.causal.as_ref();
        let parent = causal.and_then(|resolution| resolution.parent.as_ref());
        let from_text = causal.and_then(|resolution| resolution.from_text.as_ref());
        let parent_target = parent
            .and_then(|choice| choice.choice.as_deref())
            .and_then(|key| {
                context
                    .and_then(|context| context.plans.iter().find(|candidate| candidate.key == key))
            })
            .map(|candidate| candidate.node_seq);
        // A chosen key that is not one of the candidates cannot become an edge.
        let parent_state = parent.map(|choice| match choice.state.as_str() {
            "decided" if parent_target.is_none() => "unresolved",
            state => state,
        });
        let text_target = from_text
            .and_then(|choice| choice.choice.as_deref())
            .and_then(|key| key.strip_prefix('t'))
            .and_then(|seq| seq.parse::<i64>().ok());
        let from_text_state = from_text.map(|choice| match choice.state.as_str() {
            "decided" if text_target.is_none() => "unresolved",
            state => state,
        });
        let data = self
            .execute(
                WRITE_VERDICT,
                json!({
                    "session_id":request.session_id,
                    "call_seq":request.call_seq,
                    "graph_version":request.graph_version,
                    "mode":request.mode,
                    "decision":response.decision,
                    "reason":response.reason,
                    "rule":response.rule,
                    "start":response.start,
                    "jev_json":serde_json::to_string(&response.jev)
                        .map_err(|error| RepositoryError::InvalidResponse(error.to_string()))?,
                    "path_json":serde_json::to_string(&request.causal_path)
                        .map_err(|error| RepositoryError::InvalidResponse(error.to_string()))?,
                    "per_call":self.per_call,
                    "parent_target":parent_target,
                    "parent_state":parent_state,
                    "parent_probability":parent.and_then(|choice| choice.probability),
                    "parent_accepted":parent.and_then(|choice| choice.accepted),
                    "parent_candidates":parent.map(|choice| choice.candidates.clone()).unwrap_or_default(),
                    "text_target":text_target,
                    "from_text_state":from_text_state,
                    "from_text_probability":from_text.and_then(|choice| choice.probability),
                    "from_text_accepted":from_text.and_then(|choice| choice.accepted),
                    "from_text_candidates":from_text.map(|choice| choice.candidates.clone()).unwrap_or_default(),
                    "from_text_fact":from_text.is_some_and(|choice| choice.fact),
                    "from_text_basis":from_text.and_then(|choice| choice.basis.as_deref()),
                    "from_text_value":from_text.and_then(|choice| choice.value.as_deref()),
                    "seq_window":causal.map_or(self.seq_window, |value| value.seq_window),
                    "prompt_window":causal.map_or(self.prompt_window, |value| value.prompt_window),
                }),
            )
            .await?;
        if data.values.is_empty() {
            return Err(RepositoryError::NotFound);
        }
        Ok(())
    }

    async fn causal_path(
        &self,
        request: &DecisionRequest,
    ) -> Result<Option<CausalPath>, RepositoryError> {
        let parameters = json!({"session_id":request.session_id,"call_seq":request.call_seq});
        let data = self
            .execute(
                &LOAD_CHAIN.replace("{max_hops}", &(self.max_hops + 2).to_string()),
                parameters,
            )
            .await?;
        let Some(row) = data.values.first() else {
            return Ok(None);
        };
        let direct = match row.first() {
            Some(Value::Null) | None => None,
            Some(value) => Some((
                integer(value, "direct_piece")?,
                row.get(1).and_then(Value::as_bool),
            )),
        };
        let accepted = value_at(row, 3, "chain_edges")?
            .as_array()
            .cloned()
            .unwrap_or_default();
        let mut chain = value_at(row, 2, "chain_nodes")?
            .as_array()
            .cloned()
            .unwrap_or_default()
            .iter()
            .enumerate()
            .map(|(index, node)| {
                Ok(ChainNode {
                    seq: integer(
                        value_at(
                            node.as_array().map_or(&[][..], Vec::as_slice),
                            0,
                            "chain_seq",
                        )?,
                        "chain_seq",
                    )?,
                    node_type: node
                        .get(1)
                        .and_then(Value::as_str)
                        .unwrap_or_default()
                        .to_owned(),
                    parent_state: node.get(2).and_then(Value::as_str).map(str::to_owned),
                    parent_accepted: accepted.get(index).and_then(Value::as_bool),
                    from_text: Vec::new(),
                })
            })
            .collect::<Result<Vec<_>, RepositoryError>>()?;
        let node_seqs = chain.iter().map(|node| node.seq).collect::<Vec<_>>();
        let from_text = self
            .execute(
                LOAD_CHAIN_FROM_TEXT,
                json!({"session_id":request.session_id,"node_seqs":node_seqs}),
            )
            .await?;
        for row in from_text.values {
            let node_seq = integer(value_at(&row, 0, "node_seq")?, "node_seq")?;
            let link = (
                integer(value_at(&row, 1, "call_seq")?, "call_seq")?,
                integer(value_at(&row, 2, "piece_seq")?, "piece_seq")?,
                row.get(3).and_then(Value::as_bool),
            );
            for node in chain.iter_mut().filter(|node| node.seq == node_seq) {
                node.from_text.push(link);
            }
        }
        Ok(Some(build_path(
            i64::try_from(request.call_seq).unwrap_or(i64::MAX),
            direct,
            &chain,
            self.max_hops,
            self.seq_window,
            self.prompt_window,
        )))
    }
}

struct SequencePiece {
    sequence: u64,
    candidate: CausalCandidate,
}

impl Neo4jDecisionRepository {
    async fn instructing_pieces(
        &self,
        session_id: &str,
        sequences: &[u64],
    ) -> Result<Vec<SequencePiece>, RepositoryError> {
        if sequences.is_empty() {
            return Ok(Vec::new());
        }
        self.execute(
            INSTRUCTING_PIECES,
            json!({
                "session_id":session_id,"sequences":sequences,"sentence_from":self.sentence_from,
            }),
        )
        .await?
        .values
        .iter()
        .map(|row| {
            let node_seq = integer(value_at(row, 1, "piece_seq")?, "piece_seq")?;
            Ok(SequencePiece {
                sequence: unsigned(value_at(row, 0, "piece_sequence")?, "piece_sequence")?,
                candidate: CausalCandidate {
                    key: format!("t{node_seq}"),
                    node_seq,
                    body: string_at(row, 2),
                    pending: row.get(3).and_then(Value::as_bool).unwrap_or(false),
                },
            })
        })
        .collect()
    }

    fn plan_from_row(
        &self,
        row: &[Value],
        pieces: &[SequencePiece],
    ) -> Result<CausalCandidate, RepositoryError> {
        let kind = value_at(row, 0, "plan_kind")?.as_str().unwrap_or_default();
        let number = integer(value_at(row, 1, "plan_number")?, "plan_number")?;
        let node_seq = integer(value_at(row, 2, "plan_seq")?, "plan_seq")?;
        let body = string_at(row, 3);
        let mut pending = false;
        let body = match kind {
            "s" => {
                let label = if row.get(4).and_then(Value::as_bool).unwrap_or(false) {
                    "[message]"
                } else {
                    "[calls]"
                };
                let mut text = format!("{label} {body}");
                let own = pieces
                    .iter()
                    .filter(|piece| i64::try_from(piece.sequence).ok() == Some(number))
                    .collect::<Vec<_>>();
                if !own.is_empty() {
                    text.push_str(&format!("\n[instructing pieces read in s{number}]"));
                    for piece in own {
                        pending |= piece.candidate.pending;
                        text.push_str(&format!(
                            "\n{}: {}",
                            piece.candidate.key, piece.candidate.body
                        ));
                    }
                }
                text
            }
            "i" => body.chars().take(self.body_chars).collect(),
            _ => body,
        };
        Ok(CausalCandidate {
            key: format!("{kind}{number}"),
            node_seq,
            body,
            pending,
        })
    }
}

fn string_at(row: &[Value], index: usize) -> String {
    row.get(index)
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned()
}

fn integer(value: &Value, field: &str) -> Result<i64, RepositoryError> {
    value
        .as_i64()
        .ok_or_else(|| RepositoryError::InvalidResponse(format!("{field} is not an integer")))
}

fn unsigned(value: &Value, field: &str) -> Result<u64, RepositoryError> {
    value.as_u64().ok_or_else(|| {
        RepositoryError::InvalidResponse(format!("{field} is not an unsigned integer"))
    })
}

fn value_at<'a>(row: &'a [Value], index: usize, field: &str) -> Result<&'a Value, RepositoryError> {
    row.get(index)
        .ok_or_else(|| RepositoryError::InvalidResponse(format!("missing {field}")))
}

#[derive(Serialize)]
struct QueryRequest<'a> {
    statement: &'a str,
    parameters: Value,
}

#[derive(Deserialize)]
struct QueryResponse {
    #[serde(default)]
    data: Option<QueryData>,
    #[serde(default)]
    errors: Vec<QueryError>,
}

#[derive(Deserialize)]
struct QueryData {
    #[serde(default)]
    values: Vec<Vec<Value>>,
}

#[derive(Deserialize)]
struct QueryError {
    code: String,
    message: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RepositoryError {
    Unavailable(String),
    Query(String),
    InvalidResponse(String),
    NotFound,
}

impl fmt::Display for RepositoryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unavailable(error) => write!(formatter, "Neo4j unavailable: {error}"),
            Self::Query(error) => write!(formatter, "Neo4j query failed: {error}"),
            Self::InvalidResponse(error) => write!(formatter, "invalid Neo4j response: {error}"),
            Self::NotFound => formatter.write_str("requested graph version or Call was not found"),
        }
    }
}

impl Error for RepositoryError {}
