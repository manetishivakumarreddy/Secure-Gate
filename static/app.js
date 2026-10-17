const state = {
  telemetrySamples: {},
  commandSamples: {},
  commandSequence: Date.now(),
  auditEvents: [],
};

const byId = (id) => document.getElementById(id);

function setIndicator(element, decision) {
  element.textContent = decision;
  element.classList.remove('accept', 'reject');
  if (decision === 'ACCEPT') element.classList.add('accept');
  if (decision === 'REJECT') element.classList.add('reject');
}

async function fetchJson(url, options = {}) {
  const response = await fetch(url, options);
  let data;
  try {
    data = await response.json();
  } catch {
    throw new Error(`Server returned an unreadable response (${response.status}).`);
  }
  if (!response.ok) throw new Error(data.error || `Request failed (${response.status}).`);
  return data;
}

function currentTimestamp() {
  return new Date().toISOString();
}

function nextCommandSequence() {
  state.commandSequence = Math.max(Date.now(), state.commandSequence + 1);
  return state.commandSequence;
}

function makeCommand(command, overrides = {}) {
  const sequence = nextCommandSequence();
  return {
    message_id: `CMD-${sequence}`,
    sender: 'CONTROL-01',
    message_type: 'COMMAND',
    command,
    timestamp: currentTimestamp(),
    sequence,
    parameters: {},
    ...overrides,
  };
}

function setCommandEditor(message) {
  byId('command-json').value = JSON.stringify(message, null, 2);
  updateCommandLineNumbers();
}

function updateCommandLineNumbers() {
  const editor = byId('command-json');
  const count = editor.value.split('\n').length;
  byId('command-line-numbers').textContent = Array.from({ length: count }, (_, index) => index + 1).join('\n');
  byId('command-line-numbers').scrollTop = editor.scrollTop;
}

async function loadSamples() {
  const samples = await fetchJson('/api/samples');
  state.telemetrySamples = samples.telemetry;
  state.commandSamples = samples.commands;

  const telemetrySelect = byId('telemetry-sample-select');
  telemetrySelect.replaceChildren();
  Object.keys(samples.telemetry).forEach((key) => {
    const option = document.createElement('option');
    option.value = key;
    option.textContent = key;
    telemetrySelect.append(option);
  });
  if (Object.prototype.hasOwnProperty.call(state.telemetrySamples, 'valid')) {
    telemetrySelect.value = 'valid';
  }
  loadTelemetrySample(telemetrySelect.value);

  const commandSelect = byId('command-sample-select');
  commandSelect.replaceChildren();
  Object.keys(samples.commands).forEach((key) => {
    const option = document.createElement('option');
    option.value = key;
    option.textContent = key;
    commandSelect.append(option);
  });
  if (Object.prototype.hasOwnProperty.call(state.commandSamples, 'valid')) {
    commandSelect.value = 'valid';
  }

  setCommandEditor(makeCommand('STATUS_CHECK'));
}

function loadTelemetrySample(key) {
  const sample = state.telemetrySamples[key];
  if (typeof sample === 'string') {
    byId('telemetry-json').value = sample;
    return;
  }
  const message = JSON.parse(JSON.stringify(sample));
  if (message.timestamp && key !== 'invalid_stale' && key !== 'invalid_future') {
    message.timestamp = currentTimestamp();
  }
  byId('telemetry-json').value = JSON.stringify(message, null, 2);
}

function loadCommandSample(key) {
  const message = JSON.parse(JSON.stringify(state.commandSamples[key]));
  if (message.timestamp) message.timestamp = currentTimestamp();
  setCommandEditor(message);
}

function renderOverview(stats) {
  const total = stats.total || 0;
  const accepted = stats.accepted || 0;
  const rejected = stats.rejected || 0;
  const rate = total ? Math.round((accepted / total) * 100) : 0;
  byId('total-validations').textContent = total;
  byId('accepted-count').textContent = accepted;
  byId('rejected-count').textContent = rejected;
  byId('acceptance-rate').textContent = `${rate}%`;
}

function renderActivity(events) {
  const list = byId('recent-activity-list');
  list.replaceChildren();
  const recent = (events || []).slice(-5).reverse();
  if (!recent.length) {
    const item = document.createElement('li');
    item.textContent = 'No events yet.';
    list.append(item);
    return;
  }
  recent.forEach((event) => {
    const item = document.createElement('li');
    item.textContent = `${event.decision} • ${event.category} • ${event.sender || 'unknown'}`;
    list.append(item);
  });
}

async function refreshAudit() {
  const params = new URLSearchParams();
  const search = byId('audit-search').value.trim();
  const sender = byId('audit-sender-filter').value.trim();
  const decision = byId('audit-decision-filter').value;
  const category = byId('audit-category-filter').value;
  if (search) params.set('search', search);
  if (sender) params.set('sender', sender);
  if (decision) params.set('decision', decision);
  if (category) params.set('category', category);

  const response = await fetchJson(`/api/audit?${params.toString()}`);
  renderOverview(response.stats);
  renderActivity(response.events);
  state.auditEvents = response.events || [];

  const body = byId('audit-body');
  body.replaceChildren();
  const events = (response.events || []).slice().reverse();
  if (!events.length) {
    const row = document.createElement('tr');
    const cell = document.createElement('td');
    cell.colSpan = 7;
    cell.textContent = 'No audit entries found.';
    row.append(cell);
    body.append(row);
    return;
  }

  events.forEach((event) => {
    const row = document.createElement('tr');
    const detailsCell = document.createElement('td');
    const detailsButton = document.createElement('button');
    detailsButton.className = 'secondary compact';
    detailsButton.textContent = 'View';
    detailsButton.setAttribute('aria-label', `View details for ${event.event_id}`);
    detailsButton.addEventListener('click', () => {
      byId('audit-detail').textContent = JSON.stringify(event, null, 2);
    });
    detailsCell.append(detailsButton);
    row.append(detailsCell);
    [
      event.event_id,
      event.message_id || 'n/a',
      event.sender || 'n/a',
      event.category || 'unknown',
      event.decision,
      (event.timestamp || '').replace('T', ' ').replace('Z', ' UTC'),
    ].forEach((value) => {
      const cell = document.createElement('td');
      cell.textContent = value;
      row.append(cell);
    });
    body.append(row);
  });
}

function appendTextLine(container, label, value) {
  const line = document.createElement('p');
  const strong = document.createElement('strong');
  strong.textContent = `${label}: `;
  line.append(strong, document.createTextNode(value));
  container.append(line);
}

function correctionFor(ruleId) {
  const corrections = {
    JSON_SYNTAX: 'Check commas, quotes, braces, and JSON value syntax, then try again.',
    FIELD_REQUIRED: 'Add the required field or command parameter using the documented schema.',
    FIELD_TYPE: 'Change the field to the expected JSON type.',
    COMMAND_TYPE: 'Choose one of STATUS_CHECK, SENSOR_READ, DIAGNOSTIC_PING, or TELEMETRY_REQUEST.',
    SENDER_ALLOWLIST: 'Use an authorized simulator sender and only commands that sender may submit.',
    TIMESTAMP_FORMAT: 'Use an ISO 8601 timestamp with a timezone, such as a UTC timestamp ending in Z.',
    TIMESTAMP_FRESHNESS: 'Set timestamp to the current time; future timestamps are only allowed within the configured tolerance.',
    REPLAY_PROTECTION: 'Use a new message_id and a sequence greater than the last accepted sequence for this sender.',
    NUMERIC_RANGE: 'Set the parameter within its documented permitted range.',
    UNEXPECTED_FIELD: 'Remove fields or parameters not defined for this command.',
  };
  return corrections[ruleId] || 'Review this field against the documented schema and policy.';
}

function renderCommandResult(result) {
  const accepted = result.decision === 'ACCEPT';
  const panel = byId('command-result-box');
  const indicator = byId('command-indicator');
  const title = byId('command-result-title');
  const details = byId('command-result-details');

  panel.classList.remove('is-accept', 'is-reject');
  panel.classList.add(accepted ? 'is-accept' : 'is-reject');
  setIndicator(indicator, result.decision);
  title.textContent = accepted ? 'VALID — ACCEPTED' : 'INVALID — REJECTED';
  details.replaceChildren();

  if (accepted) {
    appendTextLine(details, 'Command ID', result.message_id || 'unknown');
    appendTextLine(details, 'Sender', result.sender || 'unknown');
    appendTextLine(details, 'Validation', 'All command validation checks passed.');
    appendTextLine(details, 'Execution', 'Validated only; NOT executed.');
    return;
  }

  appendTextLine(details, 'Command ID', result.message_id || 'unavailable');
  appendTextLine(details, 'Sender', result.sender || 'unavailable');
  const findings = result.findings || [];
  if (findings.length) {
    const list = document.createElement('ul');
    list.className = 'result-checks';
    findings.forEach((finding) => {
      const item = document.createElement('li');
      const summary = document.createElement('span');
      summary.textContent = `${finding.rule_id}: ${finding.message}`;
      const suggestion = document.createElement('div');
      suggestion.className = 'suggestion';
      suggestion.textContent = `Suggested correction: ${correctionFor(finding.rule_id)}`;
      item.append(summary, suggestion);
      list.append(item);
    });
    details.append(list);
  } else {
    appendTextLine(details, 'Validation', 'The validation service rejected the input.');
  }
  appendTextLine(details, 'Execution', 'Not executed.');
}

async function validatePayload(target) {
  const isCommand = target === 'command';
  const editor = byId(isCommand ? 'command-json' : 'telemetry-json');
  const indicator = byId(isCommand ? 'command-indicator' : 'telemetry-indicator');
  const details = byId(isCommand ? 'command-result-details' : 'telemetry-result-details');
  const rawText = editor.value;
  try {
    const response = await fetchJson('/api/validate', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Message-Category': target,
      },
      body: rawText,
    });
    if (isCommand) {
      renderCommandResult(response);
    } else {
      setIndicator(indicator, response.decision);
      details.replaceChildren();
      appendTextLine(details, 'Category', response.category || 'unknown');
      appendTextLine(details, 'Message ID', response.message_id || 'unknown');
      appendTextLine(details, 'Sender', response.sender || 'unknown');
      const findings = response.findings || [];
      if (findings.length) {
        const list = document.createElement('ul');
        list.className = 'result-checks';
        findings.forEach((finding) => {
          const item = document.createElement('li');
          item.textContent = `${finding.rule_id}: ${finding.message}`;
          list.append(item);
        });
        details.append(list);
      } else {
        appendTextLine(details, 'Validation', 'All checks passed.');
      }
    }
    await refreshAudit();
  } catch (error) {
    if (isCommand) {
      renderCommandResult({
        decision: 'REJECT',
        message_id: null,
        sender: null,
        findings: [{ rule_id: 'SERVER_ERROR', message: error.message }],
      });
    } else {
      setIndicator(indicator, 'REJECT');
      details.textContent = `Server error: ${error.message}`;
    }
  }
}

byId('telemetry-sample-select').addEventListener('change', (event) => {
  loadTelemetrySample(event.target.value);
});

byId('load-telemetry-sample').addEventListener('click', () => {
  const key = byId('telemetry-sample-select').value;
  loadTelemetrySample(key);
});

byId('command-sample-select').addEventListener('change', (event) => {
  loadCommandSample(event.target.value);
});

byId('load-command-sample').addEventListener('click', () => {
  loadCommandSample(byId('command-sample-select').value);
});

byId('load-valid-command').addEventListener('click', () => {
  setCommandEditor(makeCommand('STATUS_CHECK'));
});

byId('load-invalid-command').addEventListener('click', () => {
  setCommandEditor(makeCommand('UNSUPPORTED_ACTION'));
});

byId('clear-command').addEventListener('click', () => {
  byId('command-json').value = '';
  updateCommandLineNumbers();
  byId('command-indicator').textContent = 'READY';
  byId('command-indicator').classList.remove('accept', 'reject');
  byId('command-result-box').classList.remove('is-accept', 'is-reject');
  byId('command-result-title').textContent = 'Ready to validate';
  byId('command-result-details').textContent = 'Editor cleared. Submit to record a validation attempt.';
});

byId('format-command').addEventListener('click', () => {
  try {
    const parsed = JSON.parse(byId('command-json').value);
    byId('command-json').value = JSON.stringify(parsed, null, 2);
    byId('command-indicator').textContent = 'FORMATTED';
    byId('command-indicator').classList.remove('accept', 'reject');
    byId('command-result-box').classList.remove('is-accept', 'is-reject');
    byId('command-result-title').textContent = 'JSON formatted — not validated';
    byId('command-result-details').textContent = 'Formatting does not submit or validate the command.';
    updateCommandLineNumbers();
  } catch (error) {
    byId('command-indicator').textContent = 'FORMAT ERROR';
    byId('command-indicator').classList.remove('accept');
    byId('command-indicator').classList.add('reject');
    byId('command-result-box').classList.remove('is-accept');
    byId('command-result-box').classList.add('is-reject');
    byId('command-result-title').textContent = 'Could not format JSON';
    byId('command-result-details').textContent = `Malformed JSON: ${error.message}. Correct the syntax and try again.`;
  }
});

byId('command-json').addEventListener('input', updateCommandLineNumbers);
byId('command-json').addEventListener('scroll', updateCommandLineNumbers);
byId('validate-telemetry').addEventListener('click', () => validatePayload('telemetry'));
byId('validate-command').addEventListener('click', () => validatePayload('command'));
byId('refresh-audit').addEventListener('click', refreshAudit);
byId('audit-search').addEventListener('input', refreshAudit);
byId('audit-sender-filter').addEventListener('input', refreshAudit);
byId('audit-decision-filter').addEventListener('change', refreshAudit);
byId('audit-category-filter').addEventListener('change', refreshAudit);

byId('export-json').addEventListener('click', () => window.open('/api/audit/export?format=json'));
byId('export-csv').addEventListener('click', () => window.open('/api/audit/export?format=csv'));
byId('clear-audit').addEventListener('click', async () => {
  if (!window.confirm('Clear all local audit entries and reset replay protection? This cannot be undone.')) return;
  try {
    await fetchJson('/api/audit/clear', { method: 'POST' });
    await refreshAudit();
  } catch (error) {
    window.alert(`Could not clear audit log: ${error.message}`);
  }
});
byId('run-tests').addEventListener('click', async () => {
  try {
    const result = await fetchJson('/api/tests');
    byId('test-output').textContent = result.output;
  } catch (error) {
    byId('test-output').textContent = `Test run failed: ${error.message}`;
  }
});

(async function init() {
  try {
    await loadSamples();
    const schema = await fetchJson('/api/schema');
    byId('schema-view').textContent = JSON.stringify(schema, null, 2);
    await refreshAudit();
  } catch (error) {
    byId('test-output').textContent = `Could not initialize dashboard: ${error.message}`;
  }
})();
