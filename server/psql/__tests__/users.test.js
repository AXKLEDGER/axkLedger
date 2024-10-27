const request = require('supertest');
const app = require('../app');

describe('User API', () => {
    describe('POST /api/users', () => {
        it('should create a user with valid data', async () => {
            const response = await request(app)
                .post('/api/users')
                .send({
                    email: 'test@example.com',
                    password: 'password123',
                });

            expect(response.status).toBe(201);
            expect(response.body).toHaveProperty('message', 'User created successfully');
        });

        it('should return validation error for invalid email', async () => {
            const response = await request(app)
                .post('/api/users')
                .send({
                    email: 'invalid-email',
                    password: 'password123',
                });

            expect(response.status).toBe(400);
            expect(response.body).toHaveProperty('errors.email', 'Please include a valid email');
        });

        it('should return validation error for short password', async () => {
            const response = await request(app)
                .post('/api/users')
                .send({
                    email: 'test@example.com',
                    password: 'short',
                });

            expect(response.status).toBe(400);
            expect(response.body).toHaveProperty('errors.password', 'Please enter a password with 8 or more characters');
        });

        it('should return rate limit error on exceeding requests', async () => {
            for (let i = 0; i < 6; i++) {
                await request(app)
                    .post('/api/users')
                    .send({
                        email: 'test@example.com',
                        password: 'password123',
                    });
            }
            const response = await request(app)
                .post('/api/users')
                .send({
                    email: 'test@example.com',
                    password: 'password123',
                });
            expect(response.status).toBe(429);
            expect(response.body).toHaveProperty('message', 'Too many account creation requests from this IP, please try again later.');
        });
    });
});