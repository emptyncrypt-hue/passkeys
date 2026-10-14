'use strict';
const PasskeyAcceptance = (() => {
  const VERSION = '1.0.0';
  const REQUIRED = Object.freeze(['ENV', 'REGISTER', 'DUPLICATE', 'LOGIN', 'REPLAY', 'SESSION', 'LOGOUT', 'CANCEL', 'RESTART', 'UV']);
  const CASES = Object.freeze([
    ['ENV', 'Secure context and native WebAuthn available'],
    ['REGISTER', 'Physical authenticator: enroll a fresh passkey'],
    ['DUPLICATE', 'Existing username cannot be enrolled twice (409)'],
    ['LOGIN', 'Passkey assertion, user verification, authenticated session'],
    ['REPLAY', 'Reusing the same signed assertion fails (401)'],
    ['SESSION', 'HttpOnly cookie session survives page reload'],
    ['LOGOUT', 'Logout revokes access (401)'],
    ['CANCEL', 'Cancel genuine passkey prompt; no session issued'],
    ['RESTART', 'Passkey works after operator restarts backend'],
    ['UV', 'Operator confirms biometric/PIN was required and performed'],
  ]);
  function bytesFromBase64url(value) {
    if (typeof value !== 'string' || !/^[A-Za-z0-9_-]+={0,2}$/.test(value)) throw new TypeError('Invalid base64url');
    const base64 = value.replace(/-/g, '+').replace(/_/g, '/');
    const binary = atob(base64 + '='.repeat((4 - base64.length % 4) % 4));
    return Uint8Array.from(binary, char => char.charCodeAt(0));
  }
  function base64urlFromBytes(data) {
    const bytes = new Uint8Array(data);
    let binary = '';
    for (const byte of bytes) binary += String.fromCharCode(byte);
    return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
  }
  function creationOptions(json) {
    return { ...json, challenge: bytesFromBase64url(json.challenge),
      user: { ...json.user, id: bytesFromBase64url(json.user.id) },
      excludeCredentials: (json.excludeCredentials || []).map(credential => ({ ...credential, id: bytesFromBase64url(credential.id) })),
    };
  }
  function requestOptions(json) {
    return { ...json, challenge: bytesFromBase64url(json.challenge),
      allowCredentials: (json.allowCredentials || []).map(credential => ({ ...credential, id: bytesFromBase64url(credential.id) })),
    };
  }
  function registrationJSON(credential) {
    if (typeof credential.toJSON === 'function') return credential.toJSON();
    return { id: credential.id, rawId: base64urlFromBytes(credential.rawId), type: credential.type,
      response: { clientDataJSON: base64urlFromBytes(credential.response.clientDataJSON),
        attestationObject: base64urlFromBytes(credential.response.attestationObject),
        transports: credential.response.getTransports ? credential.response.getTransports() : [] },
      clientExtensionResults: credential.getClientExtensionResults(),
      authenticatorAttachment: credential.authenticatorAttachment || undefined,
    };
  }
  function assertionJSON(credential) {
    if (typeof credential.toJSON === 'function') return credential.toJSON();
    return { id: credential.id, rawId: base64urlFromBytes(credential.rawId), type: credential.type,
      response: { clientDataJSON: base64urlFromBytes(credential.response.clientDataJSON),
        authenticatorData: base64urlFromBytes(credential.response.authenticatorData),
        signature: base64urlFromBytes(credential.response.signature),
        userHandle: credential.response.userHandle ? base64urlFromBytes(credential.response.userHandle) : null },
      clientExtensionResults: credential.getClientExtensionResults(),
      authenticatorAttachment: credential.authenticatorAttachment || undefined,
    };
  }
  // No raw credentials, signatures, passkeys, challenges, or cookies in evidence.
  const SAFE_STATUSES = Object.freeze(['PASS', 'FAIL', 'NOT_RUN']);
  function evaluate(results, environment) {
    const statuses = new Map(results.map(entry => [entry.id, entry.status]));
    return !!environment?.realDeviceConfirmed && REQUIRED.every(id => statuses.get(id) === 'PASS');
  }
  return { VERSION, REQUIRED, CASES, SAFE_STATUSES, bytesFromBase64url, base64urlFromBytes, creationOptions, requestOptions, registrationJSON, assertionJSON, evaluate };
})();
if (typeof module !== 'undefined' && module.exports) module.exports = PasskeyAcceptance;
