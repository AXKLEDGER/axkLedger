const configureRoutes = (app) => {
  // Authentication API endpoints
  app.use('/afrikabal/v1/api/auth', require('./api/auth'));

  // User management API endpoints
  app.use('/afrikabal/v1/api/users', require('./api/users'));

  // Product management API endpoints
  app.use('/afrikabal/v1/api/products', require('./api/products'));

  // Order processing API endpoints
  app.use('/afrikabal/v1/api/orders', require('./api/orders'));

  // Payment processing API endpoints
  app.use('/afrikabal/v1/api/payments', require('./api/payments'));

  // Wallet management API endpoints
  app.use('/afrikabal/v1/api/wallet', require('./api/wallet'));

  // Transaction API endpoints
  app.use('/afrikabal/v1/api/transactions', require('./api/transactions'));

  // File upload API endpoints
  app.use('/afrikabal/v1/api/upload', require('./api/upload'));

  app.use((req, res) => {
    res.status(404).json({ message: 'API endpoint not found' });
  });

  // Default welcome route
  app.use('/', (req, res) => {
    res.status(200).send(`
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Afrikabal API Documentation</title>
            <style>
                * { box-sizing: border-box; margin: 0; padding: 0; }
                body {
                    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                    background: #f7f9fc;
                    color: #333;
                    display: flex;
                    flex-direction: column;
                    justify-content: center;
                    align-items: center;
                    min-height: 100vh;
                    padding: 2rem;
                    text-align: center;
                }
                h1 {
                    font-size: 2.5rem;
                    color: #A1D36C;
                    margin-bottom: 1rem;
                    text-shadow: 1px 1px 3px rgba(0, 0, 0, 0.1);
                }
                p {
                    font-size: 1rem;
                    margin: 0.5rem 0;
                    line-height: 1.5;
                    color: #555;
                }
                .container {
                    background: #ffffff;
                    border-radius: 12px;
                    box-shadow: 0 6px 15px rgba(0, 0, 0, 0.1);
                    padding: 2.5rem;
                    max-width: 600px;
                    width: 90%;
                    margin-bottom: 1.5rem;
                    transition: transform 0.3s;
                }
                .container:hover {
                    transform: translateY(-5px);
                    box-shadow: 0 8px 20px rgba(0, 0, 0, 0.15);
                }
                .highlight {
                    background-color: #A1D36C;
                    color: #fff;
                    padding: 8px 12px;
                    border-radius: 4px;
                    font-weight: bold;
                    margin: 1rem 0;
                    display: inline-block;
                }
                .cta-button {
                    display: inline-block;
                    margin-top: 1.5rem;
                    padding: 0.75rem 1.5rem;
                    font-size: 0.9rem;
                    color: #fff;
                    background-color: #A1D36C;
                    border-radius: 8px;
                    text-decoration: none;
                    transition: background-color 0.3s ease, transform 0.1s ease;
                }
                .cta-button:hover {
                    background-color: #8cbf5c;
                    color: #fff;
                    transform: scale(1.05);
                }
                .cta-button:active {
                    background-color: #7cb14e;
                    transform: scale(0.98);
                }
                a {
                    color: #A1D36C;
                    font-weight: bold;
                    text-decoration: none;
                    border-bottom: 1px solid transparent;
                    transition: color 0.3s ease, border-color 0.3s ease;
                }
                a:hover {
                    color: #8cbf5c;
                    border-color: #A1D36C;
                }
                a:active {
                    color: #7cb14e;
                }
                footer {
                    background-color: #ffffff;
                    border-top: 2px solid #A1D36C;
                    padding: 1.5rem 0;
                    width: 100%;
                    text-align: center;
                }
                footer p {
                    font-size: 0.85rem;
                    color: #555;
                }
                @media (max-width: 600px) {
                    h1 { font-size: 2rem; }
                    p { font-size: 0.9rem; }
                }
            </style>
        </head>
        <body>
            <div class="container">
                <h1>Welcome to Afrikabal API</h1>
                <p>At Afrikabal, our API empowers developers to seamlessly integrate agricultural and business data solutions, building sustainable communities through technology.</p>
                <p class="highlight">Enhance your applications by integrating market access and transactional capabilities, all backed by Afrikabal's mission to support farmers and businesses.</p>
                <p>Get started with our documentation to explore features and maximize the API's potential!</p>
                <a href="#" target="_blank" class="cta-button">View API Documentation</a>
            </div>
            <footer>
                <p>&copy; 2024 Afrikabal. All rights reserved.</p>
                <p>Connect with us on: 
                    <a href="https://linkedin.com/company/afrikabal" target="_blank">LinkedIn</a>
                    <!-- | <a href="https://twitter.com/afrikabal" target="_blank">Twitter</a> 
                    | <a href="https://facebook.com/afrikabal" target="_blank">Facebook</a> 
                    | <a href="https://instagram.com/afrikabal" target="_blank">Instagram</a> -->
                </p>
            </footer>
        </body>
        </html>
    `);
  });
};

module.exports = configureRoutes;
