const express = require('express');
const cors = require('cors');
const mysql = require('mysql');
const crypto = require('crypto');
const { generateKeyPair, SignJWT, jwtVerify } = require('jose');
const postmark = require('postmark');
const { v4: uuidv4 } = require('uuid');
const Busboy = require('busboy');
const xlsx = require('xlsx');

const app = express();
app.use(express.json());
app.use(cors({
    origin: ['https://sairamhub.vercel.app'],
    methods: ['GET', 'POST', 'PUT', 'DELETE'],
    credentials: true
}));

const db = mysql.createConnection({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    port: process.env.DB_PORT
  });

db.connect(err => {
    if (err) {
        console.error('Error connecting to the database:', err.stack);
        return;
    }
    console.log('Connected to the database');
});


app.get('/api/', (req, res) => {
    const department = req.query.department;  
    const location = req.query.location;
    const category = req.query.category; 
    const stockFilter = req.query.stock;
    const search = req.query.search; // Retrieve search term

    let query = 'SELECT * FROM product';
    let queryParams = [];

    let whereConditions = [];

    if (department !== 'Management' && location) {
        whereConditions.push('Location = ?');
        queryParams.push(location);
    }

    // Filter by category
    if (category) {
        whereConditions.push('category = ?');
        queryParams.push(category);
    }

    // Filter by stock status
    if (stockFilter === 'in_stock') {
        whereConditions.push('current_stock > 0');
    } else if (stockFilter === 'no_stock') {
        whereConditions.push('current_stock = 0');
    }

    // Search query
    if (search) {
        whereConditions.push('(name LIKE ? OR id LIKE ?)');
        queryParams.push(`%${search}%`, `%${search}%`); // Add wildcard search
    }

    // Construct the query
    if (whereConditions.length) {
        query += ' WHERE ' + whereConditions.join(' AND ');
    }

    db.query(query, queryParams, (err, results) => {
        if (err) {
            console.error('Error fetching data from database:', err);
            return res.status(500).json({ error: err.message });
        }
        return res.json(results);
    });
});


// Retrieve a product by ID
app.get("/api/product/:id", (req, res) => {
    const sql = "SELECT * FROM product WHERE `S.no` = ?";
    const id = req.params.id;
    db.query(sql, [id], (err, data) => {
        if (err) return res.status(500).json({ error: err.message });
        if (data.length === 0) return res.status(404).json({ error: "Product not found" });
        return res.json(data[0]);
    });
});

//Add products
app.post('/api/create', (req, res) => {
    console.log('Received data for creation:', req.body);

    const product = req.body; 

    if (!product.location) {
        console.error('Location is null or undefined');
        return res.status(400).json({ error: 'Location cannot be null or undefined' });
    }

    db.beginTransaction(err => {
        if (err) {
            console.error('Error starting transaction:', err.stack);
            return res.status(500).json({ error: 'Internal Server Error' });
        }

        const findAvailableSNoSql = "SELECT MIN(t1.`S.no` + 1) AS next_sno FROM product t1 LEFT JOIN product t2 ON t1.`S.no` + 1 = t2.`S.no` WHERE t2.`S.no` IS NULL";

        db.query(findAvailableSNoSql, (err, result) => {
            if (err) {
                console.error('Error finding available S.no:', err.stack);
                return db.rollback(() => res.status(500).json({ error: 'Error finding available S.no' }));
            }

            let newSNo = result[0].next_sno || 1;
            const currentStock = Math.max(product.count - (product.used + product.destroyed), 0);

            const insertProductSql = "INSERT INTO product (`S.no`, name, id, count, used, destroyed, current_stock, category, Location, barcode, incharge_name, incharge_phoneno, incharge_mail) VALUES ?";
            const values = [
                [
                    newSNo,
                    product.name,
                    product.id,
                    product.count,
                    product.used,
                    product.destroyed,
                    currentStock,
                    product.category,
                    product.location,
                    
                    product.barcode,
                    product.incharge_name,
                    product.incharge_phoneno,
                    product.incharge_mail
                ]
            ];

            console.log('Values to be inserted:', values);

            db.query(insertProductSql, [values], (err, data) => {
                if (err) {
                    console.error('Error inserting products:', err.stack);
                    return db.rollback(() => res.status(500).json({ error: 'Error inserting products' }));
                }

                db.commit(err => {
                    if (err) {
                        console.error('Error committing transaction:', err.stack);
                        return db.rollback(() => res.status(500).json({ error: 'Error committing transaction' }));
                    }

                    res.json(data);
                });
            });
        });
    });
});

//Incharge details filling
app.get('/api/incharge/:location', (req, res) => {
    const location = req.params.location;
    const sql = "SELECT incharge_name, incharge_phoneno, incharge_mail FROM incharge WHERE Location = ?";
    db.query(sql, [location], (err, data) => {
        if (err) {
            console.error('Error fetching incharge details:', err.stack);
            return res.status(500).json({ error: 'Internal Server Error' });
        }
        if (data.length === 0) {
            return res.status(404).json({ error: 'Incharge details not found' });
        }
        return res.json(data[0]);
    });
});

//changes in used,consumed etc
app.put('/api/update/:id', (req, res) => {
    const { count, destroyed, name } = req.body;
    
    const selectSql = "SELECT count, destroyed, used FROM product WHERE `S.no` = ?";
    db.query(selectSql, [req.params.id], (err, results) => {
        if (err) {
            console.error('Error fetching product details:', err.stack);
            return res.status(500).json({ error: 'Error fetching product details' });
        }
        
        const product = results[0];
        if (!product) {
            return res.status(404).json({ error: 'Product not found' });
        }

        const currentStock = Math.max(count - (product.used + destroyed), 0);
        const updateSql = "UPDATE product SET name = ?, id = ?, count = ?, used = ?, destroyed = ?, current_stock = ?, category = ?, Location = ?, barcode = ? WHERE `S.no` = ?";
        const values = [
            req.body.name,
            req.body.id,
            count,
            req.body.used,
            destroyed,
            currentStock,
            req.body.category,
            req.body.Location,
            req.body.barcode,
            req.params.id
        ];
        
        db.query(updateSql, values, (err, data) => {
            if (err) {
                console.error('Error updating product:', err.stack);
                return res.status(500).json({ error: 'Error updating product' });
            }
            console.log('Product updated successfully');
            return res.json({ message: 'Product updated successfully' });
        });
    });
});

// Delete a product by ID
app.delete('/api/product/:id', (req, res) => {
    const sql = "DELETE FROM product WHERE `S.no` = ?";
    const id = req.params.id;
    console.log('Deleting product with S.no:', id);

    db.query(sql, [id], (err, result) => {
        if (err) {
            console.error('Error deleting product:', err);
            return res.status(500).json({ error: 'Internal Server Error' });
        }

        if (result.affectedRows === 0) {
            return res.status(404).json({ error: 'Product not found' });
        }

        console.log('Deleted product with S.no:', id);
        return res.json({ message: 'Product deleted successfully' });
    });
});

app.post('/api/upload', (req, res) => {
    const busboy = Busboy({ headers: req.headers });  // No 'new' keyword
    let fileBuffer;

    busboy.on('file', (fieldname, file, filename, encoding, mimetype) => {
        const chunks = [];
        file.on('data', (data) => {
            chunks.push(data);
        }).on('end', () => {
            fileBuffer = Buffer.concat(chunks);

            // Parse the uploaded Excel file
            const workbook = xlsx.read(fileBuffer, { type: 'buffer' });
            const sheetName = workbook.SheetNames[0];
            const worksheet = workbook.Sheets[sheetName];
            const rows = xlsx.utils.sheet_to_json(worksheet);
            
            // Here, you can insert the rows into your MySQL database
            // ...

            res.send('File uploaded and processed successfully');
        });
    });

    busboy.on('finish', () => {
        if (!fileBuffer) {
            return res.status(400).send('No file uploaded');
        }
    });

    req.pipe(busboy);
});

// Retrieve all stocks
app.get('/api/stock', (req, res) => {
    const department = req.query.department;
    const location = req.query.location;
    const status = req.query.status;

    let query = 'SELECT * FROM stock';
    let queryParams = [];

    if (department && department.toLowerCase() !== 'management') {
        // Filter by department
        query += ' WHERE location = ?';
        queryParams.push(department);

        if (status) {
            query += ' AND status = ?';
            queryParams.push(status);
        }
    } else if (status) {
        // Show all data but filter by status
        query += ' WHERE status = ?';
        queryParams.push(status);
    }

    db.query(query, queryParams, (err, results) => {
        if (err) {
            console.error('Error fetching stock data from database:', err);
            return res.status(500).json({ error: err.message });
        }
        return res.json(results);
    });
}); 


// Retrieve a stock by ID
app.get("/api/stock/:id", (req, res) => {
    const sql = "SELECT * FROM stock WHERE `S.no` = ?";
    const id = req.params.id;
    db.query(sql, [id], (err, data) => {
        if (err) return res.status(500).json({ error: err.message });
        if (data.length === 0) return res.status(404).json({ error: "Stock not found" });
        return res.json(data[0]);
    });
});

//Sending Request
app.post('/api/request', (req, res) => {
    const { product, project, student_name, student_id, quantity, type, location } = req.body;

    // Insert into the requests table
    const query = 'INSERT INTO requests (product, project, student_name, student_id, quantity, type, location) VALUES (?, ?, ?, ?, ?, ?, ?)';
    db.query(query, [product, project, student_name, student_id, quantity, type, location], (error, results) => {
        if (error) {
            console.error('Error inserting request:', error);
            return res.status(500).send('Error submitting request');
        }
        res.status(201).send('Request submitted successfully');
    });
});

// Endpoint to fetch unique locations
app.get('/api/locations', (req, res) => {
  const query = 'SELECT DISTINCT location FROM requests'; 

  db.query(query, (err, result) => {
      if (err) {
          console.error(err);
          res.status(500).send('Server error');
      } else {
          res.json(result.map(row => row.location));
      }
  });
});

//RequestPopup
app.get('/api/requests', (req, res) => {
    const { department, location } = req.query;

    let query = 'SELECT * FROM requests';
    const queryParams = [];

    if (department !== 'Management') {
        query += ' WHERE location = ?';
        queryParams.push(department);
        if (location) {
            query += ' AND location = ?';
            queryParams.push(location);
        }
    } else if (location) {
        query += ' WHERE location = ?';
        queryParams.push(location);
    }

    db.query(query, queryParams, (err, result) => {
        if (err) {
            console.error(err);
            res.status(500).send('Server error');
        } else {
            res.json(result);
        }
    });
});

//Approving of request in RequestPopup
app.post('/api/approve-requests', (req, res) => {
    const approvals = req.body.approvals;

    if (!approvals || typeof approvals !== 'object') {
        return res.status(400).json({ error: 'Invalid approvals format' });
    }

    db.beginTransaction(err => {
        if (err) {
            console.error('Error starting transaction:', err.stack);
            return res.status(500).json({ error: 'Internal Server Error' });
        }

        const approvedRequests = Object.entries(approvals)
            .filter(([id, status]) => status === 'approve')
            .map(([id]) => parseInt(id, 10));

        if (approvedRequests.length === 0) {
            return res.status(400).json({ error: 'No requests approved' });
        }

        const selectApprovedRequestsSql = `SELECT * FROM requests WHERE Sno IN (${approvedRequests.join(',')})`;

        db.query(selectApprovedRequestsSql, (err, results) => {
            if (err) {
                console.error('Error fetching approved requests:', err.stack);
                return db.rollback(() => res.status(500).json({ error: 'Error fetching approved requests' }));
            }

            const insertStockSql = 'INSERT INTO stock (product, project, student_name, student_id, Quantity, type, location, created_at) VALUES ?';
            const stockValues = results.map(request => [
                request.product,
                request.project,
                request.student_name,
                request.student_id,
                request.quantity,
                request.type, 
                request.location,  
                new Date()
            ]);

            db.query(insertStockSql, [stockValues], (err, result) => {
                if (err) {
                    console.error('Error inserting into stock:', err.stack);
                    return db.rollback(() => res.status(500).json({ error: 'Error inserting into stock' }));
                }

                const deleteApprovedRequestsSql = `DELETE FROM requests WHERE Sno IN (${approvedRequests.join(',')})`;

                db.query(deleteApprovedRequestsSql, (err, result) => {
                    if (err) {
                        console.error('Error deleting approved requests:', err.stack);
                        return db.rollback(() => res.status(500).json({ error: 'Error deleting approved requests' }));
                    }

                    db.commit(err => {
                        if (err) {
                            console.error('Error committing transaction:', err.stack);
                            return db.rollback(() => res.status(500).json({ error: 'Error committing transaction' }));
                        }

                        res.json({ message: 'Requests approved and inserted into stock successfully' });
                    });
                });
            });
        });
    });
});

// Update stock status and adjust quantities
app.put('/api/updateStatus/:id', (req, res) => {
    const { status, type, quantity } = req.body;
    const id = req.params.id;

    const updateStockSql = "UPDATE stock SET status = ? WHERE `S.no` = ?";
    db.query(updateStockSql, [status, id], (err, data) => {
        if (err) {
            console.error('Error updating stock status:', err.stack);
            return res.status(500).json({ error: 'Error updating stock status', details: err.message });
        }

        if (status === 'Collected') {
            let updateProductSql = null;
            let updateProductParams = [];

            if (type === 'rent') {
                updateProductSql = "UPDATE product SET used = used + ?, current_stock = current_stock - ? WHERE name = (SELECT product FROM stock WHERE `S.no` = ?)";
                updateProductParams = [quantity, quantity, id];
            } else if (type === 'consume') {
                updateProductSql = "UPDATE product SET destroyed = destroyed + ?, current_stock = current_stock - ? WHERE name = (SELECT product FROM stock WHERE `S.no` = ?)";
                updateProductParams = [quantity, quantity, id];
            }

            if (updateProductSql) {
                db.query(updateProductSql, updateProductParams, (updateErr, updateData) => {
                    if (updateErr) {
                        console.error('Error updating product quantity:', updateErr.stack);
                        return res.status(500).json({ error: 'Error updating product quantity', details: updateErr.message });
                    }
                    console.log(`Product ${type} quantity updated successfully`);
                    return res.json({ message: 'Stock status and product quantity updated successfully' });
                });
            } else {
                return res.json({ message: 'Stock status updated successfully' });
            }
        } else {
            return res.json({ message: 'Stock status updated successfully' });
        }
    });
});
  
app.put('/api/updateType/:id', (req, res) => {
    const { type } = req.body;
    const id = req.params.id;

    if (type === 'Returned') {
        const getStockSql = "SELECT product, Quantity FROM stock WHERE `S.no` = ?";
        db.query(getStockSql, [id], (err, stockData) => {
            if (err) {
                console.error('Error fetching stock data:', err.stack);
                return res.status(500).json({ error: 'Error fetching stock data', details: err.message });
            }

            if (stockData.length === 0) {
                return res.status(404).json({ error: 'Stock item not found' });
            }

            const { product, Quantity } = stockData[0];

            const updateProductSql = "UPDATE product SET used = used - ?, current_stock = current_stock + ? WHERE name = ?";
            db.query(updateProductSql, [Quantity, Quantity, product], (updateErr, updateData) => {
                if (updateErr) {
                    console.error('Error updating product quantity:', updateErr.stack);
                    return res.status(500).json({ error: 'Error updating product quantity', details: updateErr.message });
                }

                const updateTypeSql = "UPDATE stock SET type = ? WHERE `S.no` = ?";
                db.query(updateTypeSql, [type, id], (typeErr, typeData) => {
                    if (typeErr) {
                        console.error('Error updating stock type:', typeErr.stack);
                        return res.status(500).json({ error: 'Error updating stock type', details: typeErr.message });
                    }

                    res.json({ message: 'Stock type and product quantity updated successfully' });
                });
            });
        });
    } else {
        const updateTypeSql = "UPDATE stock SET type = ? WHERE `S.no` = ?";
        db.query(updateTypeSql, [type, id], (err, data) => {
            if (err) {
                console.error('Error updating stock type:', err.stack);
                return res.status(500).json({ error: 'Error updating stock type', details: err.message });
            }

            res.json({ message: 'Stock type updated successfully' });
        });
    }
});

app.get('/api/stock-details/:productName', async (req, res) => {
  try {
    const productName = req.params.productName;
    const stocks = await db.query('SELECT student_id, student_name, Quantity FROM stock WHERE product = ?', [productName]);
    res.json(stocks);
  } catch (err) {
    console.error('Error fetching stock details:', err);
    res.status(500).send('Internal Server Error');
  }
});


app.get('/api/pending-requests-count', (req, res) => {
    const { department } = req.query;

    let query;
    let params = [];

    if (department === 'Management') {
        query = 'SELECT COUNT(*) AS count FROM requests';
    } else {
        query = 'SELECT COUNT(*) AS count FROM requests WHERE location = ?';
        params = [department];
    }

    db.query(query, params, (err, results) => {
        if (err) {
            console.error('Error executing query:', err);
            return res.status(500).json({ error: 'Internal server error' });
        }

        res.json(results[0]);
    });
});

app.get('/api/inventory-stats', (req, res) => {
    const { department } = req.query;

    let query;
    let params = [];

    if (department === 'Management') {
        query = `
            SELECT 
                SUM(count) AS total_stock, 
                SUM(used) AS items_rented, 
                SUM(destroyed) AS items_consumed,
                (SELECT SUM(Quantity) FROM stock WHERE type = 'Returned') AS items_returned
            FROM product
        `;
    } else {
        query = `
            SELECT 
                SUM(count) AS total_stock, 
                SUM(used) AS items_rented, 
                SUM(destroyed) AS items_consumed,
                (SELECT SUM(Quantity) FROM stock WHERE type = 'Returned' AND Location = ?) AS items_returned
            FROM product 
            WHERE Location = ?
        `;
        params = [department, department];
    }

    db.query(query, params, (error, results) => {
        if (error) {
            console.error('Error fetching inventory stats:', error);
            res.status(500).json({ error: 'An error occurred while fetching inventory stats' });
            return;
        }

        const stats = results[0] || {};
        console.log('Inventory stats:', stats);
        res.json({
            totalStock: stats.total_stock || 0,
            itemsRented: stats.items_rented || 0,
            itemsConsumed: stats.items_consumed || 0,
            itemsReturned: stats.items_returned || 0
        });
    });
});   

const pendingRegistrations = {};
const adminEmail = 'sit22cs086@sairamtap.edu.in'; // Admin's email address

// Postmark client setup
const postmarkClient = new postmark.ServerClient("f1773897-91cb-43f3-9ea9-a01a44cb1b4b");

// Generate RSA key pair (this should ideally be done once and stored securely)
let privateKey;
generateKeyPair('RS256').then(({ privateKey: key, publicKey }) => {
    privateKey = key;
});

// Password reset token validity duration
const resetTokenValidityDuration = 1 * 60 * 60 * 1000; // 1 hour

// Registration endpoint
app.post('/api/register', async (req, res) => {
    const { username, email, password, department, college } = req.body;

    if (!username || !email || !password || !department || !college) {
        return res.status(400).json({ error: "All fields are required." });
    }

    try {
        const sqlCheckEmail = "SELECT * FROM student WHERE email = ?";
        db.query(sqlCheckEmail, [email], async (err, results) => {
            if (err) {
                console.error('Error checking email:', err.message, err.stack);
                return res.status(500).json({ error: "An error occurred during registration." });
            }

            if (results.length > 0) {
                return res.status(400).json({ error: "Email already exists." });
            }

            const hashedPassword = crypto.createHash('sha256').update(password).digest('hex');

            // Generate a unique confirmation ID
            const confirmationId = uuidv4();

            // Store the registration details in pendingRegistrations
            pendingRegistrations[confirmationId] = { username, email, hashedPassword, department, college };

  const mailOptions = {
    From: 'sit22cs021@sairamtap.edu.in',
    To: adminEmail,
    Subject: 'New Registration Request',
    TextBody: `A new registration request has been made by ${username} (${email}). To approve, please click the following link: ${process.env.BACKEND_URL}/api/confirm/${confirmationId}`
};

            postmarkClient.sendEmail(mailOptions, (error, result) => {
                if (error) {
                    console.error('Error sending email to admin:', error.message);
                    return res.status(500).json({ error: "An error occurred while sending the email." });
                }
                console.log('Email sent to admin:', result.Message);
                res.status(200).json({ message: "Registration request sent to admin for approval." });
            });
        });
    } catch (err) {
        console.error('Error during registration:', err.message, err.stack);
        res.status(500).json({ error: "An error occurred during registration." });
    }
});

// Confirm registration endpoint
app.get('/api/confirm/:confirmationId', async (req, res) => {
    const { confirmationId } = req.params;

    const pendingUser = pendingRegistrations[confirmationId];
    if (!pendingUser) {
        return res.status(400).json({ error: "Invalid or expired confirmation link." });
    }

    const sql = "INSERT INTO student (name, email, password, department, college) VALUES (?, ?, ?, ?, ?)";
    db.query(sql, [pendingUser.username, pendingUser.email, pendingUser.hashedPassword, pendingUser.department, pendingUser.college], async (err, result) => {
        if (err) {
            console.error('Error during registration:', err.message, err.stack);
            return res.status(500).json({ error: "An error occurred during registration." });
        }
        console.log('User registered successfully:', result);

        const user = { id: result.insertId, username: pendingUser.username, email: pendingUser.email };

        const token = await new SignJWT(user)
            .setProtectedHeader({ alg: 'RS256' })
            .setExpirationTime('1h')
            .sign(privateKey);

  const userMailOptions = {
    From: 'sit22cs021@sairamtap.edu.in',
    To: pendingUser.email,
    Subject: 'Registration Approved',
    TextBody: `Hello ${pendingUser.username}, your registration has been approved. You can now log in using the following link: ${process.env.FRONTEND_URL}/login`
};

        postmarkClient.sendEmail(userMailOptions, (error, result) => {
            if (error) {
                console.error('Error sending email to user:', error.message);
                return res.status(500).json({ error: "An error occurred while sending the approval email." });
            }
            console.log('Approval email sent to user:', result.Message);

            // Remove from pendingRegistrations
            delete pendingRegistrations[confirmationId];

            res.status(200).json({ message: "Registration successful!", token, email: pendingUser.email });
        });
    });
});

// Login endpoint
app.post('/api/login', async (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).json({ error: "All fields are required." });
    }

    const sql = "SELECT * FROM student WHERE email = ?";
    db.query(sql, [email], async (err, results) => {
        if (err) {
            console.error('Login error:', err.message, err.stack);
            return res.status(500).json({ error: "An error occurred during login." });
        }

        if (results.length > 0) {
            const user = results[0];

            // Hash the entered password with crypto
            const hashedPassword = crypto.createHash('sha256').update(password).digest('hex');

            // Compare the hashed password with the stored password
            const isMatch = hashedPassword === user.password;
            if (isMatch) {
                const tokenPayload = {
                    id: user.id,
                    username: user.name,
                    email: user.email,
                    department: user.department // Include department in token payload
                };

                const token = await new SignJWT(tokenPayload)
                    .setProtectedHeader({ alg: 'RS256' })
                    .setExpirationTime('1h')
                    .sign(privateKey);

                res.status(200).json({ message: "Login successful!", token, department: user.department }); // Send department in response
            } else {
                res.status(401).json({ error: "Invalid email or password." });
            }
        } else {
            res.status(401).json({ error: "Invalid email or password." });
        }
    });
});

// Forget password endpoint
app.post('/api/forgot-password', (req, res) => {
    const { email } = req.body;

    if (!email) {
        return res.status(400).json({ error: "Email is required." });
    }

    const sqlCheckEmail = "SELECT * FROM student WHERE email = ?";
    db.query(sqlCheckEmail, [email], (err, result) => {
        if (err) {
            console.error('Error during email check:', err.message);
            return res.status(500).json({ error: "An error occurred." });
        }

        if (result.length === 0) {
            return res.status(400).json({ error: "Email does not exist." });
        }

        const resetToken = crypto.randomBytes(32).toString('hex');
        const resetTokenHash = crypto.createHash('sha256').update(resetToken).digest('hex');

        const expiresAt = new Date(Date.now() + resetTokenValidityDuration); // Token valid for 1 hour

        const sqlInsertToken = "INSERT INTO password_resets (email, token, expires_at) VALUES (?, ?, ?)";
        db.query(sqlInsertToken, [email, resetTokenHash, expiresAt], (err) => {
            if (err) {
                console.error('Error storing reset token:', err.message);
                return res.status(500).json({ error: "An error occurred while creating reset token." });
            }

            const resetLink = `${process.env.FRONTEND_URL}/reset-password?token=${resetToken}&email=${email}`;
            const mailOptions = {
                From: 'sit22cs021@sairamtap.edu.in',
                To: email,
                Subject: 'Password Reset Request',
                TextBody: `You have requested to reset your password. Please click the link to reset your password: ${resetUrl}`
            };

            postmarkClient.sendEmail(mailOptions, (error, result) => {
                if (error) {
                    console.error('Error sending password reset email:', error.message);
                    return res.status(500).json({ error: "An error occurred while sending the email." });
                }
                console.log('Password reset email sent:', result.Message);
                res.status(200).json({ message: "Password reset email sent." });
            });
        });
    });
});

// Reset password endpoint
app.post('/api/reset-password', (req, res) => {
    const { email, token, newPassword } = req.body;

    if (!email || !token || !newPassword) {
        return res.status(400).json({ error: "All fields are required." });
    }

    const tokenHash = crypto.createHash('sha256').update(token).digest('hex');
    const sqlFindToken = "SELECT * FROM password_resets WHERE email = ? AND token = ? AND expires_at > NOW()";

    db.query(sqlFindToken, [email, tokenHash], (err, result) => {
        if (err) {
            console.error('Error finding reset token:', err.message);
            return res.status(500).json({ error: "An error occurred." });
        }

        if (result.length === 0) {
            return res.status(400).json({ error: "Invalid or expired token." });
        }

        const hashedPassword = crypto.createHash('sha256').update(newPassword).digest('hex');
        const sqlUpdatePassword = "UPDATE student SET password = ? WHERE email = ?";

        db.query(sqlUpdatePassword, [hashedPassword, email], (err) => {
            if (err) {
                console.error('Error updating password:', err.message);
                return res.status(500).json({ error: "An error occurred while updating the password." });
            }

            // Delete the token after successful reset
            const sqlDeleteToken = "DELETE FROM password_resets WHERE email = ?";
            db.query(sqlDeleteToken, [email], (err) => {
                if (err) {
                    console.error('Error deleting reset token:', err.message);
                }
                res.status(200).json({ message: "Password has been successfully reset." });
            });
        });
    });
});

app.use((req, res) => {
  res.status(404).send('404 Not Found');
});


module.exports = app;
