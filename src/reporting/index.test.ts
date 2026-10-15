
describe('registerReporter', () => {
  it('refuses to replace a built-in or already registered format', async () => {
    const { registerReporter, getReporter } = await import('./index.js');
    const fake = () => ({ format: 'csv', render: () => 'replaced' });
    expect(() => registerReporter('csv', fake)).toThrow(/already registered/);
    expect(getReporter('csv').render).not.toBe(fake().render);
    registerReporter('plugin-fmt-test', fake);
    expect(() => registerReporter('plugin-fmt-test', fake)).toThrow(/already registered/);
    expect(() => registerReporter('__proto__', fake)).toThrow(/Invalid|already/);
  });
});
