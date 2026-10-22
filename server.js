require('dotenv').config();
const express = require('express');
const path = require('path');
const crypto = require('crypto');
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');

/* ------------------------------------------------------------------ */
/*  CONFIG                                                             */
/* ------------------------------------------------------------------ */
const PORT = process.env.PORT || 3000;
const { MONGODB_URI, ADMIN_PASSWORD } = process.env;
const ADMIN_USERNAME = process.env.ADMIN_USERNAME || 'admin@vr';
const JWT_SECRET = process.env.JWT_SECRET || crypto.randomBytes(32).toString('hex');
const TOKEN_TTL = '12h';

if (!MONGODB_URI) {
    console.error('Missing MONGODB_URI. Copy .env.example to .env and add your MongoDB connection string.');
    process.exit(1);
}
if (!ADMIN_PASSWORD) {
    console.error('Missing ADMIN_PASSWORD. Set it in your .env file.');
    process.exit(1);
}
if (!process.env.JWT_SECRET) {
    console.warn('JWT_SECRET is not set. Logins will reset every time the server restarts. Set JWT_SECRET in .env.');
}

/* ------------------------------------------------------------------ */
/*  HELPERS                                                            */
/* ------------------------------------------------------------------ */
const str = (v, max = 200) => String(v ?? '').trim().slice(0, max);
const num = v => (v === '' || v === null || v === undefined ? NaN : Number(v));
const round2 = n => Math.round((n + Number.EPSILON) * 100) / 100;
const escapeRegex = s => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
const httpErr = (status, message) => Object.assign(new Error(message), { status });
const wrap = fn => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);
const TIMEZONE = process.env.TIMEZONE || 'Asia/Kolkata';
const todayStr = () => new Date().toLocaleDateString('en-CA', { timeZone: TIMEZONE }); // YYYY-MM-DD in studio time
const formatBillNo = seq => `VR-${new Date().getFullYear()}-${seq}`;

function safeEqual(a, b) {
    const ha = crypto.createHash('sha256').update(String(a)).digest();
    const hb = crypto.createHash('sha256').update(String(b)).digest();
    return crypto.timingSafeEqual(ha, hb);
}

/* ------------------------------------------------------------------ */
/*  MODELS                                                             */
/* ------------------------------------------------------------------ */
const toJSON = {
    versionKey: false,
    transform: (_doc, ret) => {
        ret.id = String(ret._id);
        delete ret._id;
        delete ret.passwordHash;
        return ret;
    }
};

const Counter = mongoose.model('Counter', new mongoose.Schema(
    { _id: String, seq: { type: Number, default: 0 } },
    { versionKey: false }
));

const Employee = mongoose.model('Employee', new mongoose.Schema({
    empId: { type: String, required: true, unique: true },
    username: { type: String, required: true, unique: true, lowercase: true, trim: true },
    fullName: { type: String, default: '' },
    active: { type: Boolean, default: true }
}, { timestamps: true, toJSON }));

const Catalog = mongoose.model('Catalog', new mongoose.Schema({
    name: { type: String, required: true, trim: true },
    category: { type: String, enum: ['Frame', 'Product'], required: true },
    variants: [new mongoose.Schema({ size: String, price: { type: Number, min: 0 } }, { _id: false })]
}, { timestamps: true, toJSON }));

const Shoot = mongoose.model('Shoot', new mongoose.Schema({
    type: { type: String, enum: ['Indoor', 'Outdoor'], required: true },
    name: { type: String, required: true, trim: true },
    price: { type: Number, required: true, min: 0 },
    details: { type: String, default: '' }
}, { timestamps: true, toJSON }));

const Event = mongoose.model('Event', new mongoose.Schema({
    category: { type: String, required: true, trim: true },
    name: { type: String, required: true, trim: true },
    price: { type: Number, required: true, min: 0 },
    details: { type: String, default: '' }
}, { timestamps: true, toJSON }));

const Bill = mongoose.model('Bill', new mongoose.Schema({
    billNo: { type: String, required: true, unique: true },
    date: { type: String, required: true, index: true },
    billerUsername: String,
    billerEmpId: { type: String, index: true },
    billerName: String,
    client: { name: String, phone: String, address: String },
    items: [new mongoose.Schema({
        title: String, category: String, details: String,
        qty: Number, price: Number
    }, { _id: false })],
    subtotal: Number,
    discount: Number,
    total: Number,
    paymentMode: { type: String, enum: ['Cash', 'GPay', 'Mixed'] },
    cashAmount: { type: Number, default: 0 },
    gpayAmount: { type: Number, default: 0 }
}, { timestamps: true, toJSON }));

async function nextSeq(name) {
    const c = await Counter.findOneAndUpdate({ _id: name }, { $inc: { seq: 1 } }, { new: true, upsert: true });
    return c.seq;
}

/* ------------------------------------------------------------------ */
/*  FIRST-RUN SETUP (no default items or employees are created)        */
/* ------------------------------------------------------------------ */
async function seed() {
    // Bills start from VR-<year>-1001
    await Counter.updateOne({ _id: 'bill' }, { $setOnInsert: { seq: 1000 } }, { upsert: true });
}

/* ------------------------------------------------------------------ */
/*  APP + AUTH MIDDLEWARE                                              */
/* ------------------------------------------------------------------ */
const app = express();
app.disable('x-powered-by');
app.use(express.json({ limit: '1mb' }));
app.use(express.static(path.join(__dirname, 'public')));   // only /public is exposed

const attempts = new Map();
function loginLimiter(req, res, next) {
    const now = Date.now();
    const recent = (attempts.get(req.ip) || []).filter(t => now - t < 15 * 60 * 1000);
    if (recent.length >= 10) return res.status(429).json({ error: 'Too many login attempts. Try again in a few minutes.' });
    recent.push(now);
    attempts.set(req.ip, recent);
    next();
}

function auth(roles) {
    return wrap(async (req, _res, next) => {
        const header = req.headers.authorization || '';
        const token = header.startsWith('Bearer ') ? header.slice(7) : null;
        if (!token) throw httpErr(401, 'Please log in.');
        let payload;
        try { payload = jwt.verify(token, JWT_SECRET); }
        catch { throw httpErr(401, 'Session expired. Please log in again.'); }

        if (payload.role === 'employee') {
            // Removed or disabled employees lose access immediately.
            const emp = await Employee.findOne({ empId: payload.empId, active: true }).lean();
            if (!emp) throw httpErr(401, 'This account is no longer active.');
        }
        if (roles && !roles.includes(payload.role)) throw httpErr(403, 'You do not have permission to do this.');
        req.user = payload;
        next();
    });
}

/* ------------------------------------------------------------------ */
/*  AUTH ROUTES                                                        */
/* ------------------------------------------------------------------ */
app.post('/api/auth/admin', loginLimiter, (req, res) => {
    const { username, password } = req.body || {};
    const ok = safeEqual(str(username), ADMIN_USERNAME) & safeEqual(String(password ?? ''), ADMIN_PASSWORD);
    if (!ok) return res.status(401).json({ error: 'Invalid admin credentials.' });
    attempts.delete(req.ip);
    const user = { role: 'admin', username: ADMIN_USERNAME, empId: 'VR-ADMIN-01', name: 'Administrator' };
    res.json({ token: jwt.sign(user, JWT_SECRET, { expiresIn: TOKEN_TTL }), user });
});

// Public: list of active employees for the login dropdown (names only)
app.get('/api/auth/employees', wrap(async (_req, res) => {
    const list = await Employee.find({ active: true }).sort({ createdAt: 1 }).lean();
    res.json(list.map(e => ({ username: e.username, empId: e.empId, name: e.fullName || e.username })));
}));

// Employees sign in by choosing their name. No password.
app.post('/api/auth/employee', wrap(async (req, res) => {
    const username = str(req.body?.username, 30).toLowerCase();
    const emp = await Employee.findOne({ username, active: true });
    if (!emp) throw httpErr(401, 'Employee not found. Ask the admin to add you.');
    const user = { role: 'employee', username: emp.username, empId: emp.empId, name: emp.fullName || emp.username };
    res.json({ token: jwt.sign(user, JWT_SECRET, { expiresIn: TOKEN_TTL }), user });
}));

app.get('/api/auth/me', auth(), (req, res) => {
    const { role, username, empId, name } = req.user;
    res.json({ role, username, empId, name });
});

/* ------------------------------------------------------------------ */
/*  EMPLOYEES (admin only)                                             */
/* ------------------------------------------------------------------ */
app.get('/api/employees', auth(['admin']), wrap(async (_req, res) => {
    res.json(await Employee.find().sort({ createdAt: 1 }));
}));

app.post('/api/employees', auth(['admin']), wrap(async (req, res) => {
    const username = str(req.body.username, 30).toLowerCase();
    const fullName = str(req.body.fullName, 60);
    if (!/^[a-z0-9_.-]{3,30}$/.test(username)) throw httpErr(400, 'Username must be 3 to 30 characters: letters, numbers, _ . or -');
    if (await Employee.exists({ username })) throw httpErr(409, 'That username is already taken.');

    const seq = await nextSeq('employee');
    const emp = await Employee.create({
        empId: `VR-EMP-${String(seq).padStart(2, '0')}`,
        username, fullName
    });
    res.status(201).json(emp);
}));

app.patch('/api/employees/:id', auth(['admin']), wrap(async (req, res) => {
    const update = {};
    if (typeof req.body.active === 'boolean') update.active = req.body.active;
    if (req.body.fullName !== undefined) update.fullName = str(req.body.fullName, 60);
    const emp = await Employee.findByIdAndUpdate(req.params.id, update, { new: true });
    if (!emp) throw httpErr(404, 'Employee not found.');
    res.json(emp);
}));

app.delete('/api/employees/:id', auth(['admin']), wrap(async (req, res) => {
    const emp = await Employee.findByIdAndDelete(req.params.id);
    if (!emp) throw httpErr(404, 'Employee not found.');
    res.json({ ok: true });   // past bills keep the employee name and ID
}));

/* ------------------------------------------------------------------ */
/*  MASTER DATA (frames, products, shoots, events)                     */
/* ------------------------------------------------------------------ */
app.get('/api/master', auth(), wrap(async (_req, res) => {
    const [catalog, shoots, events] = await Promise.all([
        Catalog.find().sort({ createdAt: 1 }),
        Shoot.find().sort({ createdAt: 1 }),
        Event.find().sort({ createdAt: 1 })
    ]);
    res.json({ catalog, shoots, events });
}));

// Frames & products: one item with many size/price variants
app.post('/api/catalog', auth(['admin']), wrap(async (req, res) => {
    const category = str(req.body.category, 20);
    const name = str(req.body.name, 120);
    const size = str(req.body.size, 80);
    const price = num(req.body.price);
    if (!['Frame', 'Product'].includes(category)) throw httpErr(400, 'Category must be Frame or Product.');
    if (!name || !size || !(price >= 0)) throw httpErr(400, 'Name, size and a valid price are required.');

    let item = await Catalog.findOne({ category, name: new RegExp(`^${escapeRegex(name)}$`, 'i') });
    if (!item) {
        item = new Catalog({ category, name, variants: [] });
    }
    const existing = item.variants.find(v => v.size.toLowerCase() === size.toLowerCase());
    if (existing) existing.price = price; else item.variants.push({ size, price });
    await item.save();
    res.status(201).json(item);
}));

app.put('/api/catalog/:id/variants/:idx', auth(['admin']), wrap(async (req, res) => {
    const item = await Catalog.findById(req.params.id);
    const idx = parseInt(req.params.idx, 10);
    if (!item || !item.variants[idx]) throw httpErr(404, 'Size not found.');
    const size = str(req.body.size, 80);
    const price = num(req.body.price);
    if (!size || !(price >= 0)) throw httpErr(400, 'Size and a valid price are required.');
    item.variants[idx].size = size;
    item.variants[idx].price = price;
    await item.save();
    res.json(item);
}));

app.delete('/api/catalog/:id/variants/:idx', auth(['admin']), wrap(async (req, res) => {
    const item = await Catalog.findById(req.params.id);
    const idx = parseInt(req.params.idx, 10);
    if (!item || !item.variants[idx]) throw httpErr(404, 'Size not found.');
    item.variants.splice(idx, 1);
    if (item.variants.length === 0) await item.deleteOne(); else await item.save();
    res.json({ ok: true });
}));

app.delete('/api/catalog/:id', auth(['admin']), wrap(async (req, res) => {
    await Catalog.findByIdAndDelete(req.params.id);
    res.json({ ok: true });
}));

// Shoots and events share the same shape: group + name + price + details
function mountMaster(route, Model, groupField, allowedGroups) {
    const clean = body => {
        const o = {
            [groupField]: str(body[groupField], 40),
            name: str(body.name, 120),
            price: num(body.price),
            details: str(body.details, 300)
        };
        if (allowedGroups && !allowedGroups.includes(o[groupField])) throw httpErr(400, `${groupField} must be one of: ${allowedGroups.join(', ')}`);
        if (!o[groupField] || !o.name || !(o.price >= 0)) throw httpErr(400, 'Type, name and a valid price are required.');
        return o;
    };
    app.post(`/api/${route}`, auth(['admin']), wrap(async (req, res) => {
        res.status(201).json(await Model.create(clean(req.body)));
    }));
    app.put(`/api/${route}/:id`, auth(['admin']), wrap(async (req, res) => {
        const doc = await Model.findByIdAndUpdate(req.params.id, clean(req.body), { new: true, runValidators: true });
        if (!doc) throw httpErr(404, 'Not found.');
        res.json(doc);
    }));
    app.delete(`/api/${route}/:id`, auth(['admin']), wrap(async (req, res) => {
        await Model.findByIdAndDelete(req.params.id);
        res.json({ ok: true });
    }));
}
mountMaster('shoots', Shoot, 'type', ['Indoor', 'Outdoor']);
mountMaster('events', Event, 'category', null);

/* ------------------------------------------------------------------ */
/*  BILLS                                                              */
/* ------------------------------------------------------------------ */
app.get('/api/bills/next-number', auth(), wrap(async (_req, res) => {
    const c = await Counter.findById('bill');
    res.json({ billNo: formatBillNo((c?.seq || 1000) + 1) });
}));

app.post('/api/bills', auth(), wrap(async (req, res) => {
    const b = req.body || {};
    const client = { name: str(b.clientName, 80), phone: str(b.clientPhone, 20), address: str(b.clientAddress, 200) };
    if (!client.name || !client.phone) throw httpErr(400, 'Client name and mobile number are required.');

    const items = (Array.isArray(b.items) ? b.items : []).slice(0, 100).map(i => ({
        title: str(i.title, 120), category: str(i.category, 60), details: str(i.details, 300),
        qty: Math.floor(num(i.qty)), price: round2(num(i.price))
    }));
    if (!items.length || items.some(i => !i.title || !(i.qty >= 1 && i.qty <= 1000) || !(i.price >= 0))) {
        throw httpErr(400, 'The bill has an invalid item. Please check quantities and prices.');
    }

    // Totals are always calculated on the server.
    const subtotal = round2(items.reduce((s, i) => s + i.qty * i.price, 0));
    const discount = round2(Math.max(0, num(b.discount) || 0));
    if (discount > subtotal) throw httpErr(400, 'Discount cannot be more than the subtotal.');
    const total = round2(subtotal - discount);

    const paymentMode = str(b.paymentMode, 10);
    if (!['Cash', 'GPay', 'Mixed'].includes(paymentMode)) throw httpErr(400, 'Choose Cash, GPay or Mixed.');
    let cashAmount = 0, gpayAmount = 0;
    if (paymentMode === 'Cash') cashAmount = total;
    else if (paymentMode === 'GPay') gpayAmount = total;
    else {
        cashAmount = round2(num(b.cashAmount) || 0);
        gpayAmount = round2(num(b.gpayAmount) || 0);
        if (cashAmount < 0 || gpayAmount < 0 || Math.abs(cashAmount + gpayAmount - total) > 0.01) {
            throw httpErr(400, 'Cash and GPay amounts must add up to the bill total.');
        }
    }

    const seq = await nextSeq('bill');
    const bill = await Bill.create({
        billNo: formatBillNo(seq),
        date: /^\d{4}-\d{2}-\d{2}$/.test(b.date || '') ? b.date : todayStr(),
        // Biller comes from the login token, so it cannot be faked from the browser.
        billerUsername: req.user.username,
        billerEmpId: req.user.empId,
        billerName: req.user.name,
        client, items, subtotal, discount, total, paymentMode, cashAmount, gpayAmount
    });
    res.status(201).json(bill);
}));

app.get('/api/bills', auth(), wrap(async (req, res) => {
    const q = {};
    if (req.user.role !== 'admin') q.billerEmpId = req.user.empId;   // employees see only their own bills
    const { from, to, search } = req.query;
    if (from || to) {
        q.date = {};
        if (/^\d{4}-\d{2}-\d{2}$/.test(from || '')) q.date.$gte = from;
        if (/^\d{4}-\d{2}-\d{2}$/.test(to || '')) q.date.$lte = to;
        if (!Object.keys(q.date).length) delete q.date;
    }
    if (search) {
        const rx = new RegExp(escapeRegex(str(search, 60)), 'i');
        q.$or = [{ billNo: rx }, { 'client.name': rx }, { 'client.phone': rx }];
    }
    const limit = Math.min(parseInt(req.query.limit, 10) || 200, 1000);
    res.json(await Bill.find(q).sort({ createdAt: -1 }).limit(limit));
}));

app.get('/api/stats', auth(['admin']), wrap(async (_req, res) => {
    const group = { _id: null, revenue: { $sum: '$total' }, count: { $sum: 1 }, cash: { $sum: '$cashAmount' }, gpay: { $sum: '$gpayAmount' } };
    const [all] = await Bill.aggregate([{ $group: group }]);
    const [today] = await Bill.aggregate([{ $match: { date: todayStr() } }, { $group: group }]);
    const byEmployee = await Bill.aggregate([
        { $group: { _id: '$billerEmpId', name: { $last: '$billerUsername' }, revenue: { $sum: '$total' }, count: { $sum: 1 } } },
        { $sort: { revenue: -1 } }
    ]);
    const empty = { revenue: 0, count: 0, cash: 0, gpay: 0 };
    res.json({
        all: all || empty,
        today: today || empty,
        byEmployee: byEmployee.map(e => ({ empId: e._id, name: e.name, revenue: e.revenue, count: e.count })),
        activeEmployees: await Employee.countDocuments({ active: true })
    });
}));

/* ------------------------------------------------------------------ */
/*  PAGES + ERRORS                                                     */
/* ------------------------------------------------------------------ */
app.get('/admin', (_req, res) => res.sendFile(path.join(__dirname, 'public', 'admin.html')));
app.get('/employee', (_req, res) => res.sendFile(path.join(__dirname, 'public', 'employee.html')));
app.use('/api', (_req, res) => res.status(404).json({ error: 'Not found.' }));

app.use((err, _req, res, _next) => {
    if (err.status) return res.status(err.status).json({ error: err.message });
    if (err.name === 'ValidationError') return res.status(400).json({ error: err.message });
    if (err.name === 'CastError') return res.status(400).json({ error: 'Invalid ID.' });
    if (err.code === 11000) return res.status(409).json({ error: 'That value already exists.' });
    console.error(err);
    res.status(500).json({ error: 'Something went wrong on the server.' });
});

/* ------------------------------------------------------------------ */
/*  START                                                              */
/* ------------------------------------------------------------------ */
mongoose.connect(MONGODB_URI)
    .then(async () => {
        console.log('Connected to MongoDB');
        await seed();
        app.listen(PORT, () => console.log(`VR Photography POS running at http://localhost:${PORT}`));
    })
    .catch(err => {
        console.error('Could not connect to MongoDB:', err.message);
        process.exit(1);
    });