import { describe, before, beforeEach, afterEach, it } from 'node:test';
import assert from 'node:assert/strict';
import { createSandbox } from 'sinon';

import bootstrap, { passInteractionChecks } from '../test_helper.js';

const sinon = createSandbox();
const { any } = sinon.match;

const route = '/device';
const grantType = 'urn:ietf:params:oauth:grant-type:device_code';
const xsrf = 'foo';

describe('device flow re-entry after an interrupted confirmation', () => {
  const fixture = {};

  before(bootstrap(import.meta.url, fixture), { timeout: 3000 });
  // establish a (not logged in) session so that its state can carry the xsrf secret
  before(() => fixture.agent.get(route).expect(200), { timeout: 3000 });

  beforeEach(() => {
    fixture.getSession().state = { secret: xsrf };
  }, { timeout: 3000 });

  afterEach(() => sinon.restore(), { timeout: 3000 });

  passInteractionChecks(fixture, 'native_client_prompt', () => {
    it('keeps rejecting a confirmation while another one is (genuinely) in flight', { timeout: 3000 }, async () => {
    const spy = sinon.spy(i(fixture.provider).features.deviceFlow, 'userCodeInputSource');

    await new fixture.provider.DeviceCode({
      clientId: 'client',
      userCode: 'FOOINFLIGHT',
      inFlight: true, // a concurrent confirmation being processed right now
    }).save();

    await fixture.agent.post(route)
      .send({
        xsrf,
        confirm: 'yes',
        user_code: 'FOO-INFLIGHT',
      })
      .type('form')
      .expect(200)
      .expect(new RegExp(`<form id="op.deviceInputForm" novalidate method="post" action="http://127.0.0.1:\\d+${fixture.suitePath('/device')}">`))
      .expect(/<p class="red">The code you entered is incorrect\. Try again<\/p>/);

    assert.equal(spy.calledOnce, true);
    sinon.assert.calledWithMatch(spy, any, any, any, sinon.match((err) => {
      assert.equal(err.name, 'AlreadyUsedError');
      return true;
    }));
  });

  it('releases the code once the flow hands off to an interaction session', { timeout: 3000 }, async () => {
    const userCode = 'FOOPARKED';
    const deviceCode = await new fixture.provider.DeviceCode({
      clientId: 'client',
      userCode,
      params: {
        scope: 'openid',
        client_id: 'client',
      },
    }).save();

    // no session accountId => an interaction (login) is required => 303 to /interaction/:uid
    const { headers } = await fixture.agent.post(route)
      .send({
        xsrf,
        confirm: 'yes',
        user_code: 'FOO-PARKED',
      })
      .type('form')
      .expect(303);

    const uid = headers.location.match(/^\/interaction\/(.+)$/)[1];
    const interaction = fixture.TestAdapter.for('Interaction').syncFind(uid);
    assert.ok(interaction);
    assert.equal(interaction.deviceCode, fixture.getTokenJti(deviceCode));

    // the in-flight marker must not outlive the handoff
    const code = await fixture.provider.DeviceCode.findByUserCode(userCode);
    assert.ok(!code.inFlight);
    assert.ok(!('accountId' in Object(code)));
    assert.ok(!('error' in Object(code)));
  });

  it('lets a re-entry with the same code continue the flow instead of rejecting it', { timeout: 3000 }, async () => {
    const userCode = 'FOOREENTRY';
    await new fixture.provider.DeviceCode({
      clientId: 'client',
      userCode,
      params: {
        scope: 'openid',
        client_id: 'client',
      },
    }).save();

    // first confirmation parks at an interaction the user then abandons
    const first = await fixture.agent.post(route)
      .send({
        xsrf,
        confirm: 'yes',
        user_code: 'FOO-REENTRY',
      })
      .type('form')
      .expect(303);

    fixture.getSession().state = { secret: xsrf };

    // re-entry with the same code renders the confirmation page again (no error re-render)
    await fixture.agent.post(route)
      .send({
        xsrf,
        user_code: 'FOO-REENTRY',
      })
      .type('form')
      .expect(200)
      .expect(new RegExp(`<form id="op.deviceConfirmForm" method="post" action="http://127.0.0.1:\\d+${fixture.suitePath('/device')}">`));

    // re-confirming starts a fresh interaction rather than dying on "already used"
    const second = await fixture.agent.post(route)
      .send({
        xsrf,
        confirm: 'yes',
        user_code: 'FOO-REENTRY',
      })
      .type('form')
      .expect(303);

    assert.match(second.headers.location, /^\/interaction\/.+$/);
    assert.notEqual(second.headers.location, first.headers.location);

    // the code is still pending, not terminally consumed
    const code = await fixture.provider.DeviceCode.findByUserCode(userCode);
    assert.ok(!code.inFlight);
    assert.ok(!('accountId' in Object(code)));
    assert.ok(!('error' in Object(code)));
  });

  it('completes after re-entry and unblocks the polling device', { timeout: 3000 }, async () => {
    const userCode = 'FOOCOMPLETE';
    const deviceCode = await new fixture.provider.DeviceCode({
      clientId: 'client',
      userCode,
      params: {
        scope: 'openid',
        client_id: 'client',
      },
    }).save();

    // first confirmation parks at an interaction the user then abandons
    await fixture.agent.post(route)
      .send({
        xsrf,
        confirm: 'yes',
        user_code: 'FOO-COMPLETE',
      })
      .type('form')
      .expect(303);

    // the device is still waiting
    await fixture.agent.post('/token')
      .send({
        client_id: 'client',
        device_code: deviceCode,
        grant_type: grantType,
      })
      .type('form')
      .expect(400)
      .expect({
        error: 'authorization_pending',
        error_description: 'authorization request is still pending as the end-user hasn\'t yet completed the user interaction steps',
      });

    // the user signs in (elsewhere) and re-enters the same code
    await fixture.login({ scope: 'openid' });
    fixture.getSession().state = { secret: xsrf };

    const spy = sinon.spy(i(fixture.provider).features.deviceFlow, 'successSource');

    await fixture.agent.post(route)
      .send({
        xsrf,
        confirm: 'yes',
        user_code: 'FOO-COMPLETE',
      })
      .type('form')
      .expect(200)
      .expect(/Sign-in Success/);

    assert.equal(spy.calledOnce, true);

    const code = await fixture.provider.DeviceCode.findByUserCode(userCode);
    ((actual) => { assert.ok('accountId' in Object(actual)); assert.equal(actual.accountId, fixture.loggedInAccountId); })(code);

    // the device poll now succeeds
    await fixture.agent.post('/token')
      .send({
        client_id: 'client',
        device_code: deviceCode,
        grant_type: grantType,
      })
      .type('form')
      .expect(200)
      .expect(({ body }) => {
        assert.ok(body.access_token);
      });
  });
  });
});
