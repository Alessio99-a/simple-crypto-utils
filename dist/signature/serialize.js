export function canonicalStringify(obj) {
    if (obj === null || typeof obj !== "object") {
        return JSON.stringify(obj);
    }
    if (Array.isArray(obj)) {
        return "[" + obj.map(canonicalStringify).join(",") + "]";
    }
    const keys = Object.keys(obj).sort();
    const pairs = keys.map((key) => JSON.stringify(key) + ":" + canonicalStringify(obj[key]));
    return "{" + pairs.join(",") + "}";
}
export function serialize(data, strategy, fields) {
    switch (strategy) {
        case "canonical":
            return canonicalStringify(data);
        case "raw":
            return typeof data === "string" ? data : JSON.stringify(data);
        case "selective":
            if (!fields || fields.length === 0) {
                throw new Error("Selective strategy requires fields parameter");
            }
            const selected = {};
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
//# sourceMappingURL=serialize.js.map