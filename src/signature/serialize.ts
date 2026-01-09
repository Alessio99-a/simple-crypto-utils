import type { SerializationStrategy } from "./types";

export function canonicalStringify(obj: any): string {
  if (obj === null || typeof obj !== "object") {
    return JSON.stringify(obj);
  }

  if (Array.isArray(obj)) {
    return "[" + obj.map(canonicalStringify).join(",") + "]";
  }

  const keys = Object.keys(obj).sort();
  const pairs = keys.map(
    (key) => JSON.stringify(key) + ":" + canonicalStringify(obj[key])
  );
  return "{" + pairs.join(",") + "}";
}

export function serialize(
  data: any,
  strategy: SerializationStrategy,
  fields?: string[]
): string {
  switch (strategy) {
    case "canonical":
      return canonicalStringify(data);

    case "raw":
      return typeof data === "string" ? data : JSON.stringify(data);

    case "selective":
      if (!fields || fields.length === 0) {
        throw new Error("Selective strategy requires fields parameter");
      }
      const selected: any = {};
      for (const field of fields) {
        if (field in data) {
          selected[field] = data[field];
        }
      }
      return canonicalStringify(selected);

    default:
      throw new Error(`Unknown strategy: ${strategy}`);
  }
}
