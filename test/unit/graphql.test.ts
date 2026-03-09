import { describe, it, expect } from 'vitest';
import { graphqlCheck } from '../../src/scanner/active/graphql.js';

describe('GraphQL check: metadata', () => {
  it('has correct name and category', () => {
    expect(graphqlCheck.name).toBe('graphql');
    expect(graphqlCheck.category).toBe('info-disclosure');
  });
});
