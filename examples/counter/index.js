export class Counter {
  constructor(ctx) {
    this.ctx = ctx;
  }

  async fetch() {
    const old = (await this.ctx.storage.get("count")) || 0;
    const value = old + 1;
    await this.ctx.storage.put("count", value);
    return new Response(String(value));
  }
}

export default {
  fetch(request, env) {
    const id = env.COUNTER.idFromName("first-vps");
    return env.COUNTER.get(id).fetch(request);
  }
};
