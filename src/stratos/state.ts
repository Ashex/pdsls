import type { StratosEnrollment } from "@northskysocial/stratos-client";
import { createSignal } from "solid-js";

/**
 * Enrollment of the authenticated user.
 * undefined = not yet checked, null = checked and not enrolled.
 */
export const [stratosEnrollment, setStratosEnrollment] = createSignal<
  StratosEnrollment | null | undefined
>(undefined);

/**
 * Enrollment of the repo currently being browsed (set by the repo layout).
 * undefined = not yet checked, null = checked and not enrolled.
 */
export const [targetEnrollment, setTargetEnrollment] = createSignal<
  StratosEnrollment | null | undefined
>(undefined);

/** User preference for Stratos mode, persisted across reloads. */
const [active, setActive] = createSignal(localStorage.stratosActive === "true");

export const stratosActive = active;

export const setStratosActive = (value: boolean | ((prev: boolean) => boolean)) => {
  const next = typeof value === "function" ? value(active()) : value;
  localStorage.stratosActive = String(next);
  setActive(next);
};

/** True when the user's and the browsed repo's enrollments target different services. */
export const serviceMismatch = () => {
  const own = stratosEnrollment();
  const target = targetEnrollment();
  if (!own || !target) return false;
  return own.service !== target.service;
};

/**
 * Effective Stratos mode: the user prefers Stratos, is enrolled, and the
 * browsed repo is enrolled on the same service. Navigating between enrolled
 * and non-enrolled repos transparently switches transports while keeping
 * the preference.
 */
export const stratosMode = () =>
  stratosActive() && !!stratosEnrollment() && !!targetEnrollment() && !serviceMismatch();
