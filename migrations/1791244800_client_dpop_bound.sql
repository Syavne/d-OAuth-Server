-- RFC 9449 §5 DPoP-bound access tokens: persist the registration opt-in.
--
-- Forward-only: deterministic, no DROP / down path. The default false keeps
-- every existing client unconstrained until it re-registers or is updated.

ALTER TABLE oauth_clients
  ADD COLUMN dpop_bound_access_tokens boolean NOT NULL DEFAULT false;
