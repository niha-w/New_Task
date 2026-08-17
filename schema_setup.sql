DROP VIEW IF EXISTS vip_view;
DROP VIEW IF EXISTS customer_orders_view;
DROP TABLE IF EXISTS orders;
DROP TABLE IF EXISTS customers;

CREATE TABLE customers (
    id INT PRIMARY KEY,
    name VARCHAR(100),
    email VARCHAR(150) COMMENT 'sensitive:pii',
    ssn VARCHAR(11) COMMENT 'sensitive:pii',
    signup_date DATE
);

CREATE TABLE orders (
    id INT PRIMARY KEY,
    customer_id INT,
    amount DECIMAL(10,2),
    status VARCHAR(20)
);

INSERT INTO customers (id, name, email, ssn, signup_date) VALUES
(1, 'Asha Rao', 'asha@example.com', '123-45-6789', '2024-01-15'),
(2, 'Ben Cole', 'ben@example.com', '987-65-4321', '2024-02-20');

INSERT INTO orders (id, customer_id, amount, status) VALUES
(1, 1, 1500.00, 'flagged'),
(2, 2, 300.00, 'normal');

CREATE VIEW customer_orders_view AS
SELECT c.id, c.name, c.email AS contact_email, o.amount,
       CASE WHEN o.status = 'flagged' THEN c.ssn ELSE NULL END AS flagged_ssn
FROM customers c JOIN orders o ON c.id = o.customer_id;

CREATE VIEW vip_view AS
SELECT id, contact_email, flagged_ssn
FROM customer_orders_view
WHERE amount > 1000;


SELECT JSON_ARRAYAGG(
    JSON_OBJECT('table', table_name, 'column', column_name,
                'category', SUBSTRING(column_comment, LENGTH('sensitive:') + 1))
) AS seed_json
FROM information_schema.columns
WHERE table_schema = DATABASE()
  AND column_comment LIKE 'sensitive:%';


SELECT JSON_ARRAYAGG(
    JSON_OBJECT('view', table_name, 'sql', view_definition)
) AS views_json
FROM information_schema.views
WHERE table_schema = DATABASE();


SELECT JSON_ARRAYAGG(
    JSON_OBJECT('table_name', table_name, 'column_name', column_name, 'data_type', data_type)
) AS schema_json
FROM information_schema.columns
WHERE table_schema = DATABASE()
  AND table_name NOT IN (SELECT table_name FROM information_schema.views WHERE table_schema = DATABASE());