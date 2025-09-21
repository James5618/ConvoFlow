// Health check endpoint
module.exports = (app) => {
  app.get('/health', (req, res) => {
    res.status(200).json({ 
      status: 'healthy',
      timestamp: new Date().toISOString(),
      environment: process.env.NODE_ENV || 'development',
      version: process.env.npm_package_version || '1.0.0'
    });
  });

  // Metrics endpoint for Prometheus
  app.get('/metrics', (req, res) => {
    // Basic metrics - can be enhanced with prom-client
    const metrics = {
      uptime: process.uptime(),
      memory: process.memoryUsage(),
      timestamp: Date.now()
    };
    res.status(200).json(metrics);
  });
};
