import { describe, expect, it } from "vitest";

import type { PropertyType } from "../api/types";
import { displayValue, formatCount, formatDate, formatDateTime } from "./format";

const property = (overrides: Partial<PropertyType>): PropertyType => ({
  label: "X",
  type: "text",
  required: false,
  searchable: false,
  values: null,
  ...overrides,
});

describe("formatDate", () => {
  it("writes a calendar date the French way", () => {
    expect(formatDate("2026-11-18")).toBe("18 nov. 2026");
  });

  it("does not shift a calendar date across time zones", () => {
    expect(formatDate("2026-01-01")).toBe("1 janv. 2026");
  });

  it("returns the raw text when it is not a date", () => {
    expect(formatDate("bientôt")).toBe("bientôt");
  });
});

describe("formatDateTime", () => {
  it("writes day and time", () => {
    expect(formatDateTime("2026-11-24T10:42:00+00:00", "UTC")).toBe("24 nov. 2026 à 10:42");
  });
});

describe("formatCount", () => {
  it("groups thousands", () => {
    expect(formatCount(1792)).toMatch(/^1\s792$/);
  });
});

describe("displayValue", () => {
  it("shows the label of an enum value", () => {
    const prop = property({ type: "enum", values: { known: "Avéré", unknown: "Non connu" } });
    expect(displayValue(prop, "known")).toBe("Avéré");
  });

  it("falls back to the stored value for an undeclared enum value", () => {
    const prop = property({ type: "enum", values: { known: "Avéré" } });
    expect(displayValue(prop, "other")).toBe("other");
  });

  it("formats dates", () => {
    expect(displayValue(property({ type: "date" }), "2026-11-21")).toBe("21 nov. 2026");
  });

  it("answers yes or no for booleans", () => {
    expect(displayValue(property({ type: "boolean" }), true)).toBe("Oui");
    expect(displayValue(property({ type: "boolean" }), false)).toBe("Non");
  });

  it("joins lists", () => {
    expect(displayValue(property({ type: "text_list" }), ["CWE-73", "CWE-94"])).toBe(
      "CWE-73, CWE-94",
    );
  });

  it("shows nothing for a missing value", () => {
    expect(displayValue(property({ type: "date" }), undefined)).toBe("");
  });
});
