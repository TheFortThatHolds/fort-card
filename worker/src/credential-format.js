// Provider defaults only select an HTTP authentication format; card scope and approval remain unchanged.
export function credentialFormat(request) {
  const devOnly = request.allowed_hosts?.length === 1 && request.allowed_hosts[0] === "dev.to";
  const header = request.header ?? (devOnly ? "api-key" : "Authorization");
  const header_prefix = request.header_prefix ?? (devOnly ? "" : "Bearer ");
  if (typeof header !== "string" || !/^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/.test(header)) throw new Error("Invalid credential header");
  if (typeof header_prefix !== "string" || /[\r\n]/.test(header_prefix)) throw new Error("Invalid credential header prefix");
  return { header, header_prefix };
}
