/*
 * BOYS VS GIRLS ESports API bridge
 * Social App Express Backend-এর সঙ্গে যুক্ত হবে।
 *
 * Mount:
 * app.use('/api/tournament', createTournamentRouter({
 *   pool, requireAuth, requireAdmin
 * }));
 *
 * Render Environment Variables:
 * SUPABASE_URL
 * SUPABASE_SERVICE_ROLE_KEY
 */

const express = require('express');
const crypto = require('crypto');

module.exports = function createTournamentRouter({
  pool,
  requireAuth,
  requireAdmin
}) {
  if (!pool) {
    throw new Error(
      'Tournament API requires the Social App PostgreSQL pool.'
    );
  }

  if (
    !process.env.SUPABASE_URL ||
    !process.env.SUPABASE_SERVICE_ROLE_KEY
  ) {
    throw new Error(
      'SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY are required.'
    );
  }

  const router = express.Router();

  const base =
    process.env.SUPABASE_URL.replace(/\/$/, '') + '/rest/v1';

  const serviceKey = process.env.SUPABASE_SERVICE_ROLE_KEY;

  const adminEmail = String(
    process.env.TOURNAMENT_ADMIN_EMAIL || ''
  ).trim().toLowerCase();

  // Supabase REST API helper
  async function sb(
    path,
    {
      method = 'GET',
      body,
      prefer = 'return=representation'
    } = {}
  ) {
    const response = await fetch(`${base}/${path}`, {
      method,

      headers: {
        apikey: serviceKey,
        Authorization: `Bearer ${serviceKey}`,
        'Content-Type': 'application/json',
        Prefer: prefer
      },

      body:
        body === undefined
          ? undefined
          : JSON.stringify(body)
    });

    const raw = await response.text();

    let data = null;

    try {
      data = raw ? JSON.parse(raw) : null;
    } catch (_) {
      data = raw;
    }

    if (!response.ok) {
      const err = new Error(
        data?.message ||
        data?.hint ||
        'Tournament database request failed.'
      );

      err.status = response.status;

      throw err;
    }

    return data;
  }

  // Supabase RPC helper
  async function rpc(name, args) {
    return sb(`rpc/${name}`, {
      method: 'POST',
      body: args,
      prefer: 'return=representation'
    });
  }

  function clean(value, max = 200) {
    return String(value ?? '')
      .trim()
      .slice(0, max);
  }

  function amount(value) {
    const n = Number(value);

    if (
      !Number.isFinite(n) ||
      n <= 0 ||
      n > 10000000
    ) {
      return null;
    }

    return Math.round(n * 100) / 100;
  }

  function wrap(handler) {
    return async (req, res, next) => {
      try {
        await handler(req, res);
      } catch (e) {
        next(e);
      }
    };
  }

  // Social App user-এর সঙ্গে Tournament player identity mapping
  async function identity(user) {
    const socialId = String(user.id);

    const found = await pool.query(
      `SELECT tournament_player_id
       FROM ft_tournament_identities
       WHERE social_user_id=$1
       LIMIT 1`,
      [socialId]
    );

    if (found.rowCount) {
      return found.rows[0].tournament_player_id;
    }

    const playerId = crypto.randomUUID();

    const displayName = String(
      user.username || user.email || 'Player'
    ).slice(0, 80);

    const inserted = await pool.query(
      `INSERT INTO ft_tournament_identities
       (social_user_id,tournament_player_id)
       VALUES($1,$2)
       ON CONFLICT(social_user_id)
       DO NOTHING
       RETURNING tournament_player_id`,
      [socialId, playerId]
    );

    const finalId =
      inserted.rows[0]?.tournament_player_id ||
      (
        await pool.query(
          `SELECT tournament_player_id
           FROM ft_tournament_identities
           WHERE social_user_id=$1`,
          [socialId]
        )
      ).rows[0].tournament_player_id;

    await sb('profiles?on_conflict=id', {
      method: 'POST',

      body: [{
        id: finalId,
        username: user.username || null,
        display_name: displayName,

        role:
          String(user.role).toLowerCase() === 'admin'
            ? 'admin'
            : 'player'
      }],

      prefer: 'resolution=merge-duplicates,return=minimal'
    });

    await sb('wallets?on_conflict=user_id', {
      method: 'POST',

      body: [{
        user_id: finalId,
        balance: 0
      }],

      prefer: 'resolution=ignore-duplicates,return=minimal'
    });

    return finalId;
  }

  async function player(req) {
    const id = await identity(req.user);

    return {
      id,
      social: req.user
    };
  }

  // Admin verification
  async function assertTournamentAdmin(req, res) {
    if (
      String(req.user?.role || '').toLowerCase() !== 'admin'
    ) {
      res.status(403).json({
        error: 'Social App administrator access required.'
      });

      return false;
    }

    if (
      adminEmail &&
      String(req.user?.email || '').toLowerCase() !== adminEmail
    ) {
      res.status(403).json({
        error:
          'This Social App admin is not the configured Tournament administrator.'
      });

      return false;
    }

    await identity(req.user);

    return true;
  }

  // সব API-তে Social App Login বাধ্যতামূলক
  router.use(requireAuth);

  // নিজের Profile, Wallet ও Registration
  router.get('/me', wrap(async (req, res) => {
    const p = await player(req);

    const rows = await sb(
      `profiles?select=id,username,display_name,free_fire_uid,role&id=eq.${encodeURIComponent(p.id)}&limit=1`
    );

    const profile = rows?.[0] || null;

    if (profile) {
      profile.role =
        String(req.user.role).toLowerCase() === 'admin'
          ? 'admin'
          : 'player';
    }

    const [registrations, wallets] = await Promise.all([
      sb(
        `tournament_registrations?select=tournament_id,status,joined_at&player_id=eq.${encodeURIComponent(p.id)}&status=eq.registered`
      ),

      sb(
        `wallets?select=balance&user_id=eq.${encodeURIComponent(p.id)}&limit=1`
      )
    ]);

    res.json({
      user: {
        id: p.id,
        email: req.user.email,
        role: req.user.role
      },

      profile,

      registrations: registrations || [],

      wallet: {
        balance: Number(wallets?.[0]?.balance || 0)
      },

      is_admin:
        String(req.user.role).toLowerCase() === 'admin'
    });
  }));

  // Profile Update
  router.patch('/profile', wrap(async (req, res) => {
    const p = await player(req);

    const display_name = String(
      req.body.display_name || ''
    ).trim().slice(0, 80);

    const username = String(
      req.body.username || ''
    ).trim().slice(0, 40) || null;

    const free_fire_uid = String(
      req.body.free_fire_uid || ''
    ).trim().slice(0, 40) || null;

    if (!display_name) {
      return res.status(400).json({
        error: 'Display name is required.'
      });
    }

    const rows = await sb(
      `profiles?id=eq.${encodeURIComponent(p.id)}`,
      {
        method: 'PATCH',

        body: {
          display_name,
          username,
          free_fire_uid
        }
      }
    );

    res.json({
      profile: rows?.[0] || null
    });
  }));

  // Tournament List
  router.get('/tournaments', wrap(async (_req, res) => {
    const rows = await sb(
      'tournaments?select=*&order=scheduled_at.asc'
    );

    const ids = (rows || []).map(x => x.id);

    let counts = {};

    if (ids.length) {
      const regs = await sb(
        `tournament_registrations?select=tournament_id&status=eq.registered&tournament_id=in.(${ids.join(',')})`
      );

      for (const r of regs || []) {
        counts[r.tournament_id] =
          (counts[r.tournament_id] || 0) + 1;
      }
    }

    res.json({
      tournaments: (rows || []).map(t => ({
        ...t,
        registered_count: counts[t.id] || 0
      })),

      counts
    });
  }));

  // Wallet Balance
  router.get('/wallet', wrap(async (req, res) => {
    const p = await player(req);

    const rows = await sb(
      `wallets?select=balance&user_id=eq.${encodeURIComponent(p.id)}&limit=1`
    );

    res.json({
      balance: Number(rows?.[0]?.balance || 0)
    });
  }));

  // Payment Methods
  router.get('/payment-methods', wrap(async (req, res) => {
    const all =
      req.query.all === '1' &&
      String(req.user?.role || '').toLowerCase() === 'admin';

    if (all && !await assertTournamentAdmin(req, res)) {
      return;
    }

    const filter = all ? '' : '&enabled=eq.true';

    const rows = await sb(
      `wallet_payment_methods?select=method_code,display_name,instructions,receiver_details,enabled&order=display_name.asc${filter}`
    );

    res.json({
      methods: rows || []
    });
  }));

  // নিজের Registrations
  router.get('/registrations/mine', wrap(async (req, res) => {
    const p = await player(req);

    const rows = await sb(
      `tournament_registrations?select=tournament_id,status,joined_at&player_id=eq.${encodeURIComponent(p.id)}&status=eq.registered`
    );

    res.json({
      registrations: rows || []
    });
  }));

  // নিজের Transactions
  router.get('/transactions/mine', wrap(async (req, res) => {
    const p = await player(req);

    const rows = await sb(
      `wallet_transactions?select=transaction_type,amount,direction,description,created_at&user_id=eq.${encodeURIComponent(p.id)}&order=created_at.desc&limit=50`
    );

    res.json({
      transactions: rows || []
    });
  }));

  // Admin Requests List
  router.get(
    '/admin/requests',
    requireAdmin,
    wrap(async (req, res) => {
      if (!await assertTournamentAdmin(req, res)) {
        return;
      }

      const type = clean(req.query.type, 20);

      const filter =
        ['deposit', 'withdrawal'].includes(type)
          ? `&request_type=eq.${type}`
          : '';

      const rows = await sb(
        `wallet_requests?select=id,user_id,request_type,method_code,amount,account_info,transaction_reference,status,admin_note,created_at&order=created_at.desc&limit=100${filter}`
      );

      res.json({
        requests: rows || []
      });
    })
  );

  // Admin Registrations
  router.get(
    '/admin/registrations/:tournamentId',
    requireAdmin,
    wrap(async (req, res) => {
      if (!await assertTournamentAdmin(req, res)) {
        return;
      }

      const id = encodeURIComponent(
        req.params.tournamentId
      );

      const rows = await sb(
        `tournament_registrations?select=tournament_id,player_id,status,profiles(display_name,username,free_fire_uid)&tournament_id=eq.${id}&order=status.asc`
      );

      res.json({
        registrations: rows || []
      });
    })
  );

  // Leaderboard
  router.get('/leaderboard', wrap(async (_req, res) => {
    const rows = await sb(
      'match_results?select=player_id,total_points,kills,placement,profiles(display_name,username)&order=total_points.desc&limit=100'
    );

    res.json({
      results: rows || []
    });
  }));

  // Join Tournament
  router.post('/join', wrap(async (req, res) => {
    const p = await player(req);

    const tournamentId = clean(
      req.body.tournament_id,
      80
    );

    if (!/^[0-9a-f-]{36}$/i.test(tournamentId)) {
      return res.status(400).json({
        error: 'Invalid tournament ID.'
      });
    }

    const result = await rpc(
      'bvg_join_tournament',
      {
        p_player_id: p.id,
        p_tournament_id: tournamentId
      }
    );

    res.json(
      Array.isArray(result)
        ? (result[0] || {})
        : (result || {})
    );
  }));

  // Deposit Request
  router.post('/wallet/deposit', wrap(async (req, res) => {
    const p = await player(req);

    const value = amount(req.body.amount);

    const method = clean(
      req.body.method_code,
      60
    );

    const reference = clean(
      req.body.transaction_reference,
      180
    );

    const account = clean(
      req.body.account_info,
      180
    );

    if (!value || !method || !reference) {
      return res.status(400).json({
        error:
          'Valid amount, payment method and transaction reference are required.'
      });
    }

    const result = await rpc(
      'bvg_request_wallet_deposit',
      {
        p_user_id: p.id,
        p_method_code: method,
        p_amount: value,
        p_account_info: account,
        p_reference: reference
      }
    );

    res.status(201).json(
      Array.isArray(result)
        ? (result[0] || {})
        : (result || {})
    );
  }));

  // Withdrawal Request
  router.post('/wallet/withdraw', wrap(async (req, res) => {
    const p = await player(req);

    const value = amount(req.body.amount);

    const method = clean(
      req.body.method_code,
      60
    );

    const account = clean(
      req.body.account_info,
      180
    );

    if (!value || !method || !account) {
      return res.status(400).json({
        error:
          'Valid amount, payment method and account details are required.'
      });
    }

    const result = await rpc(
      'bvg_request_wallet_withdrawal',
      {
        p_user_id: p.id,
        p_method_code: method,
        p_amount: value,
        p_account_info: account
      }
    );

    res.status(201).json(
      Array.isArray(result)
        ? (result[0] || {})
        : (result || {})
    );
  }));

  // Admin Create Tournament
  router.post(
    '/admin/tournaments',
    requireAdmin,
    wrap(async (req, res) => {
      if (!await assertTournamentAdmin(req, res)) {
        return;
      }

      const title = clean(req.body.title, 120);
      const mode = clean(req.body.mode, 40);

      const scheduled = new Date(
        req.body.scheduled_at
      );

      const fee = Number(
        req.body.entry_fee || 0
      );

      const prize = Number(
        req.body.prize_pool || 0
      );

      const slots = Number.parseInt(
        req.body.max_players,
        10
      );

      if (
        !title ||
        !mode ||
        !Number.isFinite(scheduled.getTime()) ||
        !Number.isFinite(fee) ||
        fee < 0 ||
        !Number.isFinite(prize) ||
        prize < 0 ||
        !Number.isInteger(slots) ||
        slots < 2 ||
        slots > 1000
      ) {
        return res.status(400).json({
          error: 'Invalid tournament details.'
        });
      }

      const rows = await sb(
        'tournaments',
        {
          method: 'POST',

          body: [{
            title,
            mode,

            map: clean(req.body.map, 80) || null,

            entry_fee: fee,
            prize_pool: prize,
            max_players: slots,

            scheduled_at: scheduled.toISOString(),

            status: 'open',

            created_by: (await player(req)).id
          }]
        }
      );

      res.status(201).json({
        tournament: rows?.[0] || null
      });
    })
  );

  // Admin Edit Tournament
  router.patch(
    '/admin/tournaments/:id',
    requireAdmin,
    wrap(async (req, res) => {
      if (!await assertTournamentAdmin(req, res)) {
        return;
      }

      const id = encodeURIComponent(req.params.id);
      const b = req.body || {};

      const patch = {};

      for (const k of [
        'title',
        'mode',
        'map',
        'status'
      ]) {
        if (b[k] !== undefined) {
          patch[k] = clean(
            b[k],
            k === 'title' ? 120 : 80
          );
        }
      }

      for (const k of [
        'entry_fee',
        'prize_pool'
      ]) {
        if (b[k] !== undefined) {
          const n = Number(b[k]);

          if (!Number.isFinite(n) || n < 0) {
            return res.status(400).json({
              error: `Invalid ${k}.`
            });
          }

          patch[k] = n;
        }
      }

      if (b.max_players !== undefined) {
        const n = Number(b.max_players);

        if (
          !Number.isInteger(n) ||
          n < 2 ||
          n > 1000
        ) {
          return res.status(400).json({
            error: 'Invalid max_players.'
          });
        }

        patch.max_players = n;
      }

      if (b.scheduled_at !== undefined) {
        const d = new Date(b.scheduled_at);

        if (!Number.isFinite(d.getTime())) {
          return res.status(400).json({
            error: 'Invalid scheduled_at.'
          });
        }

        patch.scheduled_at = d.toISOString();
      }

      if (
        !Object.keys(patch).length &&
        b.room_id === undefined &&
        b.room_password === undefined
      ) {
        return res.status(400).json({
          error: 'No changes supplied.'
        });
      }

      const rows = Object.keys(patch).length
        ? await sb(
            `tournaments?id=eq.${id}`,
            {
              method: 'PATCH',
              body: patch
            }
          )
        : [];

      if (
        b.room_id !== undefined ||
        b.room_password !== undefined
      ) {
        await sb(
          'match_rooms?on_conflict=tournament_id',
          {
            method: 'POST',

            body: [{
              tournament_id: req.params.id,

              room_id:
                clean(b.room_id, 100) || null,

              room_password:
                clean(b.room_password, 100) || null,

              updated_at: new Date().toISOString()
            }],

            prefer:
              'resolution=merge-duplicates,return=minimal'
          }
        );

        await sb(
          'tournament_secrets?on_conflict=tournament_id',
          {
            method: 'POST',

            body: [{
              tournament_id: req.params.id,

              room_id:
                clean(b.room_id, 100) || null,

              room_password:
                clean(b.room_password, 100) || null,

              updated_at: new Date().toISOString()
            }],

            prefer:
              'resolution=merge-duplicates,return=minimal'
          }
        );
      }

      res.json({
        tournament: rows?.[0] || null,
        updated: true
      });
    })
  );

  // Admin Delete Tournament
  router.delete(
    '/admin/tournaments/:id',
    requireAdmin,
    wrap(async (req, res) => {
      if (!await assertTournamentAdmin(req, res)) {
        return;
      }

      const id = encodeURIComponent(req.params.id);

      const [regs, results] = await Promise.all([
        sb(
          `tournament_registrations?select=id&tournament_id=eq.${id}&limit=1`
        ),

        sb(
          `match_results?select=id&tournament_id=eq.${id}&limit=1`
        )
      ]);

      // Player registration/result থাকলে Delete করা যাবে না।
      if (regs?.length || results?.length) {
        return res.status(409).json({
          error:
            'This tournament has registrations or results. Change its status instead of deleting it.'
        });
      }

      await sb(
        `tournaments?id=eq.${id}`,
        {
          method: 'DELETE',
          prefer: 'return=minimal'
        }
      );

      res.json({
        deleted: true
      });
    })
  );

  // Admin Room Details
  router.get(
    '/admin/tournaments/:id/room',
    requireAdmin,
    wrap(async (req, res) => {
      if (!await assertTournamentAdmin(req, res)) {
        return;
      }

      const rows = await sb(
        `tournament_secrets?select=room_id,room_password&tournament_id=eq.${encodeURIComponent(req.params.id)}&limit=1`
      );

      res.json({
        room: rows?.[0] || null
      });
    })
  );

  // Registered Player Room Details
  router.get('/rooms/:id', wrap(async (req, res) => {
    const p = await player(req);

    const tid = encodeURIComponent(req.params.id);

    const reg = await sb(
      `tournament_registrations?select=id&tournament_id=eq.${tid}&player_id=eq.${encodeURIComponent(p.id)}&status=eq.registered&limit=1`
    );

    if (
      !reg?.length &&
      String(req.user.role).toLowerCase() !== 'admin'
    ) {
      return res.status(403).json({
        error:
          'Join this tournament to view room details.'
      });
    }

    if (
      String(req.user.role).toLowerCase() === 'admin' &&
      !await assertTournamentAdmin(req, res)
    ) {
      return;
    }

    const rows = await sb(
      `tournament_secrets?select=room_id,room_password&tournament_id=eq.${tid}&limit=1`
    );

    res.json({
      room: rows?.[0] || null
    });
  }));

  // Admin Remove Registration
  router.delete(
    '/admin/registrations/:tournamentId/:playerId',
    requireAdmin,
    wrap(async (req, res) => {
      if (!await assertTournamentAdmin(req, res)) {
        return;
      }

      await sb(
        `tournament_registrations?tournament_id=eq.${encodeURIComponent(req.params.tournamentId)}&player_id=eq.${encodeURIComponent(req.params.playerId)}`,
        {
          method: 'DELETE',
          prefer: 'return=minimal'
        }
      );

      res.json({
        removed: true
      });
    })
  );

  // Admin Approve / Reject Deposit or Withdrawal
  router.post(
    '/admin/requests/:id/:action',
    requireAdmin,
    wrap(async (req, res) => {
      if (!await assertTournamentAdmin(req, res)) {
        return;
      }

      const action = req.params.action;

      if (!['approve', 'reject'].includes(action)) {
        return res.status(400).json({
          error: 'Invalid review action.'
        });
      }

      const admin = await player(req);

      const result = await rpc(
        action === 'approve'
          ? 'bvg_admin_approve_wallet_request'
          : 'bvg_admin_reject_wallet_request',

        {
          p_request_id: req.params.id,
          p_admin_id: admin.id,
          p_admin_note: clean(
            req.body?.admin_note,
            500
          )
        }
      );

      res.json(
        Array.isArray(result)
          ? (result[0] || {})
          : (result || {})
      );
    })
  );

  // Admin Payment Method Update
  router.patch(
    '/admin/payment-methods/:code',
    requireAdmin,
    wrap(async (req, res) => {
      if (!await assertTournamentAdmin(req, res)) {
        return;
      }

      const code = encodeURIComponent(
        req.params.code
      );

      const patch = {};

      if (req.body.receiver_details !== undefined) {
        patch.receiver_details =
          clean(req.body.receiver_details, 1000) || null;
      }

      if (req.body.instructions !== undefined) {
        patch.instructions =
          clean(req.body.instructions, 2000) || null;
      }

      if (req.body.enabled !== undefined) {
        patch.enabled = !!req.body.enabled;
      }

      const rows = await sb(
        `wallet_payment_methods?method_code=eq.${code}`,
        {
          method: 'PATCH',
          body: patch
        }
      );

      res.json({
        method: rows?.[0] || null
      });
    })
  );

  // Error Handler
  router.use((err, _req, res, _next) => {
    console.error(
      'Tournament API:',
      err.message
    );

    res.status(
      err.status && err.status < 500
        ? err.status
        : 500
    ).json({
      error:
        err.status && err.status < 500
          ? err.message
          : 'Tournament service error.'
    });
  });

  return router;
};
