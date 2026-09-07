/**
 * Canary Test Suite: XSS via dangerouslySetInnerHTML
 *
 * This file DELIBERATELY contains an XSS vulnerability pattern.
 * It exists to validate that the scanner pipeline detects it.
 *
 * Expected detections: ESLint (react/no-unsanitized, no-danger),
 *                       CodeQL
 */

import React from 'react';

// ── Pattern 1: dangerouslySetInnerHTML without sanitization ──────────────────
function UserGeneratedContent({ htmlContent }: { htmlContent: string }) {
  // VULNERABLE: User-controlled HTML is rendered directly without sanitization.
  // An attacker can inject <script> tags leading to stored XSS.
  return (
    <div dangerouslySetInnerHTML={{ __html: htmlContent }} />
  );
}

// ── Pattern 2: Setting innerHTML directly ────────────────────────────────────
function LegacyComponent({ content }: { content: string }) {
  const divRef = React.useRef<HTMLDivElement>(null);

  React.useEffect(() => {
    // VULNERABLE: Direct innerHTML assignment — XSS vector.
    if (divRef.current) {
      divRef.current.innerHTML = content;
    }
  }, [content]);

  return <div ref={divRef} />;
}

// ── SAFE version (for contrast) ─────────────────────────────────────────────
function SafeContent({ htmlContent }: { htmlContent: string }) {
  // SAFE: Content is rendered as text, not HTML.
  return (
    <div>{htmlContent}</div>
  );
}

// SAFE: Sanitized HTML using a dedicated library
function SanitizedContent({ htmlContent }: { htmlContent: string }) {
  // In production: import DOMPurify and sanitize before rendering
  const sanitized = DOMPurify.sanitize(htmlContent);
  return (
    <div dangerouslySetInnerHTML={{ __html: sanitized }} />
  );
}

// Minimal type declaration for the example
declare const DOMPurify: {
  sanitize(html: string): string;
};
