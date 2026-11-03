/** Session namespaces are independent from the fleet dashboard. */
export const dashboardEnvironmentSchema = Object.freeze({
  SESSION_ISSUER: {default: 'cindertrace-console'},
  SESSION_AUDIENCE: {default: 'cindertrace-console'},
});
/** @param {string} name @param {Record<string, string | undefined>} env */
export function readDashboardEnvironment(name, env = process.env) {
  const definition = dashboardEnvironmentSchema[name];
  if (!definition) throw new Error(`${name} is not a security console session setting`);
  return env[name]?.trim() || definition.default;
}
