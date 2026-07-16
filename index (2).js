/**
 * Aurum Gold — Cloud Functions
 * ============================================================
 * These functions move the money-moving operations that used to run
 * directly in the browser (wallet balance changes, trade escrow/payout,
 * deposit/withdraw confirmation) onto the server, using the Admin SDK.
 *
 * WHY THIS EXISTS
 * Firestore Security Rules alone cannot stop a signed-in user from
 * opening their browser console and calling
 *   db.collection('wallets').doc(myUid).update({ balance: 999999 })
 * if the rules allow that path to be written by the client at all.
 * The only real fix is to never let the client write balance-changing
 * fields directly — instead the client calls one of these functions,
 * and only server-side code (which the client can't tamper with)
 * decides what value actually gets written.
 *
 * WHAT YOU MUST DO BEFORE THIS WORKS
 * 1. Upgrade the Firebase project to the Blaze (pay-as-you-go) plan.
 *    Cloud Functions require Blaze even though usage will likely stay
 *    within the free monthly quota for an app this size.
 * 2. Install the Firebase CLI locally: npm install -g firebase-tools
 * 3. From this "functions" folder: npm install
 * 4. From the project root: firebase deploy --only functions
 * 5. Update firestore.rules (a new version is provided alongside this
 *    file) so wallets/trades can no longer be written directly by
 *    either app — only these functions may touch them.
 * 6. The User App and Admin App HTML files already ship with the
 *    matching client-side calls to these functions (see the separate
 *    explanation for what changed there).
 * ============================================================
 */

const functions = require('firebase-functions');
const admin = require('firebase-admin');
admin.initializeApp();
const db = admin.firestore();

/* ------------------------------------------------------------
   Helpers
------------------------------------------------------------ */

// Confirms the caller's Firebase Auth session belongs to an email
// present in the Firestore "admins" allowlist collection.
async function assertIsAdmin(context) {
  if (!context.auth || !context.auth.token || !context.auth.token.email) {
    throw new functions.https.HttpsError('unauthenticated', 'Sign in required.');
  }
  const adminDoc = await db.collection('admins').doc(context.auth.token.email).get();
  if (!adminDoc.exists) {
    throw new functions.https.HttpsError('permission-denied', 'This account is not on the admin allowlist.');
  }
}

// Confirms the caller's Firebase Auth session (an anonymous sign-in,
// established when the person logs into the User App) is the same
// session that was linked to this account at login time. This is what
// stands in for "this really is that user" since the User App has its
// own custom Firestore-based accounts rather than using Firebase Auth
// as the primary login.
async function assertOwnsAccount(context, uid) {
  if (!context.auth) {
    throw new functions.https.HttpsError('unauthenticated', 'Sign in required.');
  }
  const accountDoc = await db.collection('otp_requests').doc(uid).get();
  if (!accountDoc.exists) {
    throw new functions.https.HttpsError('not-found', 'Account not found.');
  }
  if (accountDoc.data().authUid !== context.auth.uid) {
    throw new functions.https.HttpsError(
      'permission-denied',
      'This browser session is not linked to that account. Please log out and back in.'
    );
  }
}

/* ------------------------------------------------------------
   fetchGoldSpotPrice — the single source of truth for what "the gold
   price" is at any moment, used both when a trade is opened (entryPrice)
   and when it resolves (exitPrice). Trades win or lose based on whether
   the real price moved in the direction the trader picked — nobody,
   including an admin, sets the outcome directly.
   Swap the URL below for whatever licensed/paid spot-gold feed the
   business ends up contracting (e.g. a market-data vendor) before going
   to production; this free endpoint is fine for development but has no
   uptime/accuracy guarantee.
------------------------------------------------------------ */
async function fetchGoldSpotPrice() {
  const res = await fetch('https://api.metals.live/v1/spot/gold');
  if (!res.ok) throw new Error('Gold price feed returned ' + res.status);
  const body = await res.json();
  // This feed returns [{ gold: 2384.10 }] or [[timestamp, price]] depending
  // on version — handle both shapes defensively.
  const price = Array.isArray(body)
    ? (typeof body[0] === 'object' ? Object.values(body[0])[0] : body[0][1])
    : body.price;
  const num = Number(price);
  if (!Number.isFinite(num) || num <= 0) throw new Error('Gold price feed returned an invalid value');
  return num;
}

// Trading room definitions — the single source of truth for timer/profit/
// min/max/VIP rules. The client mirrors these values for display, but this
// is the copy that actually gets enforced, since a tampered client can't
// change what runs here.
const TRADE_ROOMS = {
  30:  { profitPercent: 5,  min: 200,   max: 2000,   vip: false },
  60:  { profitPercent: 10, min: 3000,  max: 10000,  vip: false },
  90:  { profitPercent: 15, min: 15000, max: 30000,  vip: false },
  120: { profitPercent: 20, min: 50000, max: 100000, vip: true  },
};
const VIP_VOLUME_THRESHOLD = 30000; // cumulative trading volume (USD) needed to unlock the 120s room

/* ------------------------------------------------------------
   linkAccountSession — called by the User App right after it finds a
   matching account by phone/email at login time.
   This does two jobs at once:
     1. Verifies the password SERVER-SIDE (the old version of this app
        compared the password in the browser, which a modified client
        could simply skip).
     2. On success, writes authUid = the caller's Firebase Auth uid
        onto that account's otp_requests document — but only from
        inside this trusted server function. A client can never set
        authUid directly (see firestore.rules), so nobody can hijack
        another person's wallet by overwriting that link themselves.
   The client must already be signed in anonymously
   (firebase.auth().signInAnonymously()) before calling this.
------------------------------------------------------------ */
exports.linkAccountSession = functions.https.onCall(async (data, context) => {
  if (!context.auth) {
    throw new functions.https.HttpsError('unauthenticated', 'Sign in required.');
  }
  const { uid, password } = data || {};
  if (!uid || !password) {
    throw new functions.https.HttpsError('invalid-argument', 'Missing uid or password.');
  }
  const accountRef = db.collection('otp_requests').doc(uid);
  const accountSnap = await accountRef.get();
  if (!accountSnap.exists) {
    throw new functions.https.HttpsError('not-found', 'Account not found.');
  }
  const account = accountSnap.data();
  if (account.status !== 'verified') {
    throw new functions.https.HttpsError('failed-precondition', 'Account is not verified yet.');
  }
  if (account.passwordHash !== password) {
    throw new functions.https.HttpsError('permission-denied', 'Incorrect password.');
  }
  await accountRef.update({ authUid: context.auth.uid });
  return { ok: true };
});

/* ------------------------------------------------------------
   placeTrade — called by the User App's BUY/SELL buttons.
   Validates the stake against the live server-held balance and the
   timer/profit combination (so a tampered client can't invent a
   180s/+50% trade for the price of a 30s/+15% one), then escrows the
   stake and records the trade.
------------------------------------------------------------ */
exports.placeTrade = functions.https.onCall(async (data, context) => {
  const { uid, market, direction, amountUsd, timerSec } = data || {};
  await assertOwnsAccount(context, uid);

  // KYC gate — no order proceeds unless the account is verified. This is
  // re-checked here even though the client also checks it, because the
  // client check is only a convenience; this is the one that's actually
  // enforced.
  const kycSnap = await db.collection('kyc_requests').doc(uid).get();
  if (!kycSnap.exists || kycSnap.data().status !== 'verified') {
    throw new functions.https.HttpsError('failed-precondition', 'KYC verification is required before trading.');
  }

  const room = TRADE_ROOMS[timerSec];
  if (room === undefined) {
    throw new functions.https.HttpsError('invalid-argument', 'Invalid timer selection.');
  }
  if (!['buy', 'sell'].includes(direction)) {
    throw new functions.https.HttpsError('invalid-argument', 'Invalid direction.');
  }
  if (!amountUsd || amountUsd < room.min || amountUsd > room.max) {
    throw new functions.https.HttpsError(
      'invalid-argument',
      `This room only accepts trades between $${room.min.toLocaleString()} and $${room.max.toLocaleString()}.`
    );
  }

  const walletRef = db.collection('wallets').doc(uid);
  const tradeRef = db.collection('trades').doc();

  // Fetched before the transaction (transactions should stay side-effect
  // free / retry-safe) — this is the price the trade's win/lose outcome
  // will be judged against at resolution time.
  let entryPrice;
  try {
    entryPrice = await fetchGoldSpotPrice();
  } catch (priceEx) {
    throw new functions.https.HttpsError('unavailable', 'Live gold price feed is temporarily unavailable — please try again in a moment.');
  }

  await db.runTransaction(async (tx) => {
    const walletSnap = await tx.get(walletRef);
    const walletData = walletSnap.exists ? walletSnap.data() : {};
    const balance = walletData.balance || 0;
    const totalVolume = walletData.totalVolume || 0;

    if (balance < amountUsd) {
      throw new functions.https.HttpsError('failed-precondition', 'Insufficient balance.');
    }
    // 120s VIP Elite room — locked server-side until cumulative trading
    // volume clears the threshold, regardless of what the client sent.
    if (room.vip && totalVolume < VIP_VOLUME_THRESHOLD) {
      throw new functions.https.HttpsError(
        'permission-denied',
        `VIP Elite room requires $${VIP_VOLUME_THRESHOLD.toLocaleString()} in cumulative trading volume.`
      );
    }

    tx.set(walletRef, {
      balance: admin.firestore.FieldValue.increment(-amountUsd),
      totalVolume: admin.firestore.FieldValue.increment(amountUsd),
    }, { merge: true });
    tx.set(tradeRef, {
      uid,
      market: market || 'gold',
      direction,
      amountUsd,
      timerSec,
      profitPercent: room.profitPercent,
      entryPrice,
      status: 'active',
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
      resolvesAt: Date.now() + timerSec * 1000,
    });
  });

  return { tradeId: tradeRef.id };
});

/* ------------------------------------------------------------
   resolveDueTrades — scheduled function, runs every minute.
   Finds any trade whose countdown has finished and is still "active",
   fetches the current live gold price, and resolves win/lose by
   comparing it against the entryPrice captured when the trade was
   opened: a "buy" wins if the price went up, a "sell" wins if it went
   down. Nobody — including an admin — can set the outcome directly;
   the only thing that decides it is where the real price moved.
   Because this runs on a fixed schedule rather than the instant the
   timer hits zero, resolution can lag by up to ~60 seconds — the User
   App listens for the status change and shows the win/lose popup
   whenever it arrives.
------------------------------------------------------------ */
exports.resolveDueTrades = functions.pubsub.schedule('every 1 minutes').onRun(async () => {
  const now = Date.now();
  const dueSnap = await db.collection('trades')
    .where('status', '==', 'active')
    .where('resolvesAt', '<=', now)
    .get();

  if (dueSnap.empty) return null;

  let exitPrice;
  try {
    exitPrice = await fetchGoldSpotPrice();
  } catch (priceEx) {
    // Leave these trades active — they'll be picked up and resolved on
    // the next run once the price feed is reachable again, rather than
    // resolving them on a guess.
    console.error('resolveDueTrades: gold price feed unavailable, will retry next run', priceEx);
    return null;
  }

  for (const tradeDoc of dueSnap.docs) {
    const trade = tradeDoc.data();
    const entryPrice = typeof trade.entryPrice === 'number' ? trade.entryPrice : null;
    // A trade opened before this price-based system shipped (no
    // entryPrice on file) can't be judged fairly — treat as a push
    // (stake returned, no profit) rather than guessing.
    let won = false;
    let push = false;
    if (entryPrice === null) {
      push = true;
    } else if (exitPrice === entryPrice) {
      push = true; // flat market — stake returned, no win/lose either way
    } else {
      won = trade.direction === 'buy' ? exitPrice > entryPrice : exitPrice < entryPrice;
    }

    const profit = won ? trade.amountUsd * (trade.profitPercent / 100) : 0;
    const payout = push ? trade.amountUsd : (won ? trade.amountUsd + profit : 0);
    const walletRef = db.collection('wallets').doc(trade.uid);

    await db.runTransaction(async (tx) => {
      if (payout > 0) {
        tx.set(walletRef, { balance: admin.firestore.FieldValue.increment(payout) }, { merge: true });
        tx.set(walletRef.collection('transactions').doc(), {
          type: push ? 'push' : 'win',
          amount: payout,
          createdAt: admin.firestore.FieldValue.serverTimestamp(),
        });
      }
      tx.update(tradeDoc.ref, {
        status: push ? 'push' : (won ? 'won' : 'lost'),
        exitPrice,
        payoutUsd: payout,
        resolvedAt: admin.firestore.FieldValue.serverTimestamp(),
      });
    });
  }
  return null;
});

/* ------------------------------------------------------------
   confirmDeposit / confirmWithdraw — called by the Admin App when
   staff click "Confirm" on a pending deposit_requests/withdraw_requests
   document. Only an allowlisted admin account may call these.
------------------------------------------------------------ */
exports.confirmDeposit = functions.https.onCall(async (data, context) => {
  await assertIsAdmin(context);
  const { reqId, usdAmount } = data || {};
  if (!usdAmount || usdAmount <= 0) {
    throw new functions.https.HttpsError('invalid-argument', 'Invalid USD amount.');
  }
  const reqRef = db.collection('deposit_requests').doc(reqId);
  const reqSnap = await reqRef.get();
  if (!reqSnap.exists) throw new functions.https.HttpsError('not-found', 'Deposit request not found.');
  const uid = reqSnap.data().uid;
  const walletRef = db.collection('wallets').doc(uid);

  await db.runTransaction(async (tx) => {
    tx.set(walletRef, {
      balance: admin.firestore.FieldValue.increment(usdAmount),
      totalDeposited: admin.firestore.FieldValue.increment(usdAmount),
    }, { merge: true });
    tx.set(walletRef.collection('transactions').doc(), {
      type: 'deposit',
      amount: usdAmount,
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
    });
    tx.update(reqRef, {
      status: 'completed',
      usdAmount,
      completedAt: admin.firestore.FieldValue.serverTimestamp(),
    });
  });

  return { ok: true };
});

exports.confirmWithdraw = functions.https.onCall(async (data, context) => {
  await assertIsAdmin(context);
  const { reqId, usdAmount } = data || {};
  if (!usdAmount || usdAmount <= 0) {
    throw new functions.https.HttpsError('invalid-argument', 'Invalid USD amount.');
  }
  const reqRef = db.collection('withdraw_requests').doc(reqId);
  const reqSnap = await reqRef.get();
  if (!reqSnap.exists) throw new functions.https.HttpsError('not-found', 'Withdrawal request not found.');
  const uid = reqSnap.data().uid;
  const walletRef = db.collection('wallets').doc(uid);

  await db.runTransaction(async (tx) => {
    const walletSnap = await tx.get(walletRef);
    const balance = walletSnap.exists ? (walletSnap.data().balance || 0) : 0;
    if (balance < usdAmount) {
      throw new functions.https.HttpsError('failed-precondition', 'User balance is too low for this withdrawal.');
    }
    tx.set(walletRef, { balance: admin.firestore.FieldValue.increment(-usdAmount) }, { merge: true });
    tx.set(walletRef.collection('transactions').doc(), {
      type: 'withdraw',
      amount: usdAmount,
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
    });
    tx.update(reqRef, {
      status: 'completed',
      usdAmount,
      completedAt: admin.firestore.FieldValue.serverTimestamp(),
    });
  });

  return { ok: true };
});

/* ------------------------------------------------------------
   manualWalletAdjustment — called by the Admin App's Wallet view for
   a direct credit/debit that didn't come through a deposit/withdraw
   request (e.g. a correction).
------------------------------------------------------------ */
exports.manualWalletAdjustment = functions.https.onCall(async (data, context) => {
  await assertIsAdmin(context);
  const { uid, type, amountUsd } = data || {}; // type: 'deposit' | 'withdraw'
  if (!uid || !['deposit', 'withdraw'].includes(type)) {
    throw new functions.https.HttpsError('invalid-argument', 'Invalid request.');
  }
  if (!amountUsd || amountUsd <= 0) {
    throw new functions.https.HttpsError('invalid-argument', 'Invalid USD amount.');
  }
  const walletRef = db.collection('wallets').doc(uid);

  await db.runTransaction(async (tx) => {
    if (type === 'deposit') {
      tx.set(walletRef, {
        balance: admin.firestore.FieldValue.increment(amountUsd),
        totalDeposited: admin.firestore.FieldValue.increment(amountUsd),
      }, { merge: true });
    } else {
      const walletSnap = await tx.get(walletRef);
      const balance = walletSnap.exists ? (walletSnap.data().balance || 0) : 0;
      if (balance < amountUsd) {
        throw new functions.https.HttpsError('failed-precondition', 'Insufficient balance.');
      }
      tx.set(walletRef, { balance: admin.firestore.FieldValue.increment(-amountUsd) }, { merge: true });
    }
    tx.set(walletRef.collection('transactions').doc(), {
      type,
      amount: amountUsd,
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
    });
  });

  return { ok: true };
});
