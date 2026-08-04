export default {
  async fetch(request) {
    const url = new URL(request.url);
    return Response.json({
      product: "RandallFlare",
      source: "GitHub",
      path: url.pathname,
      deployed: true
    });
  }
};
