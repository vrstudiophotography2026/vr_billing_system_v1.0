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
const BRANCHES = ['Branch 1', 'Branch 2'];
const EXPENSE_BRANCHES = ['General', ...BRANCHES];

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
const todayStr = () => new Date().toLocaleDateString('en-CA', { timeZone: TIMEZONE }); // YYYY-MM-DD in shop time
const formatBillNo = seq => `VR-${new Date().getFullYear()}-${seq}`;

// Accepts YYYY-MM-DD, DD-MM-YYYY or DD/MM/YYYY and returns a valid YYYY-MM-DD (or null).
function parseDate(v) {
    const s = str(v, 10);
    let y, mo, d, m;
    if ((m = /^(\d{4})-(\d{2})-(\d{2})$/.exec(s))) { y = +m[1]; mo = +m[2]; d = +m[3]; }
    else if ((m = /^(\d{2})[-/](\d{2})[-/](\d{4})$/.exec(s))) { d = +m[1]; mo = +m[2]; y = +m[3]; }
    else return null;
    const dt = new Date(Date.UTC(y, mo - 1, d));
    if (dt.getUTCFullYear() !== y || dt.getUTCMonth() !== mo - 1 || dt.getUTCDate() !== d) return null;
    return `${String(y).padStart(4, '0')}-${String(mo).padStart(2, '0')}-${String(d).padStart(2, '0')}`;
}

function safeEqual(a, b) {
    const ha = crypto.createHash('sha256').update(String(a)).digest();
    const hb = crypto.createHash('sha256').update(String(b)).digest();
    return crypto.timingSafeEqual(ha, hb);
}

// Validates a Cash / GPay / Mixed payment for a given amount.
function splitPayment(b, amount) {
    const mode = str(b.paymentMode, 10);
    if (!['Cash', 'GPay', 'Mixed'].includes(mode)) throw httpErr(400, 'Choose Cash, GPay or Mixed.');
    let cash = 0, gpay = 0;
    if (mode === 'Cash') cash = amount;
    else if (mode === 'GPay') gpay = amount;
    else {
        cash = round2(num(b.cashAmount) || 0);
        gpay = round2(num(b.gpayAmount) || 0);
        if (cash < 0 || gpay < 0 || Math.abs(cash + gpay - amount) > 0.01) {
            throw httpErr(400, 'Cash and GPay amounts must add up to the amount being paid.');
        }
    }
    return { mode, cash, gpay };
}

// Date range filter on a YYYY-MM-DD string field.
function dateRange(query) {
    const from = parseDate(query.from);
    const to = parseDate(query.to);
    if (!from && !to) return null;
    const r = {};
    if (from) r.$gte = from;
    if (to) r.$lte = to;
    return r;
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

const Passport = mongoose.model('Passport', new mongoose.Schema({
    name: { type: String, required: true, trim: true },
    price: { type: Number, required: true, min: 0 },
    details: { type: String, default: '' }
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

const Expense = mongoose.model('Expense', new mongoose.Schema({
    date: { type: String, required: true, index: true },       // YYYY-MM-DD
    amount: { type: Number, required: true, min: 0 },
    note: { type: String, default: '' },
    branch: { type: String, enum: EXPENSE_BRANCHES, default: 'General' },
    createdBy: String
}, { timestamps: true, toJSON }));

const Bill = mongoose.model('Bill', new mongoose.Schema({
    billNo: { type: String, required: true, unique: true },
    date: { type: String, required: true, index: true },      // YYYY-MM-DD. For advance orders this becomes the completion date
    orderDate: String,                                          // date the order was first taken
    branch: { type: String, enum: BRANCHES, default: 'Branch 1', index: true },
    // 'Advance' = balance still pending (hidden from sales). Old bills have no status and count as completed.
    status: { type: String, enum: ['Completed', 'Advance'], default: 'Completed', index: true },
    billerUsername: String,
    billerEmpId: { type: String, index: true },
    billerName: String,
    client: { name: String, phone: String, address: String },
    items: [new mongoose.Schema({
        title: String, category: String, details: String, branch: String,
        qty: Number, price: Number
    }, { _id: false })],
    subtotal: Number,
    discount: Number,
    total: Number,
    paymentMode: { type: String, enum: ['Cash', 'GPay', 'Mixed'] },
    cashAmount: { type: Number, default: 0 },                  // money collected so far
    gpayAmount: { type: Number, default: 0 },
    // advance details
    advance: { type: Number, default: 0 },
    advanceMode: { type: String, enum: ['Cash', 'GPay', 'Mixed'] },
    advanceCash: { type: Number, default: 0 },
    advanceGpay: { type: Number, default: 0 },
    balance: { type: Number, default: 0 },                     // total - advance
    balanceMode: { type: String, enum: ['Cash', 'GPay', 'Mixed'] },
    balanceCash: { type: Number, default: 0 },
    balanceGpay: { type: Number, default: 0 },
    completedAt: Date,
    completedBy: String
}, { timestamps: true, toJSON }));

async function nextSeq(name) {
    const c = await Counter.findOneAndUpdate({ _id: name }, { $inc: { seq: 1 } }, { new: true, upsert: true });
    return c.seq;
}

/* ------------------------------------------------------------------ */
/*  FIRST-RUN SETUP                                                    */
/* ------------------------------------------------------------------ */
async function seed() {
    // Bills start from VR-<year>-1001
    await Counter.updateOne({ _id: 'bill' }, { $setOnInsert: { seq: 1000 } }, { upsert: true });
    // Older bills (before branches existed) belong to Branch 1
    await Bill.updateMany({ branch: { $exists: false } }, { $set: { branch: 'Branch 1' } });
    // Older bills (before advance orders existed) are completed sales
    await Bill.updateMany({ status: { $exists: false } }, { $set: { status: 'Completed' } });
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
const USERNAME_RX = /^[a-z0-9_.-]{3,30}$/;

app.get('/api/employees', auth(['admin']), wrap(async (_req, res) => {
    res.json(await Employee.find().sort({ createdAt: 1 }));
}));

app.post('/api/employees', auth(['admin']), wrap(async (req, res) => {
    const username = str(req.body.username, 30).toLowerCase();
    const fullName = str(req.body.fullName, 60);
    if (!USERNAME_RX.test(username)) throw httpErr(400, 'Username must be 3 to 30 characters: letters, numbers, _ . or -');
    if (await Employee.exists({ username })) throw httpErr(409, 'That username is already taken.');

    const seq = await nextSeq('employee');
    const emp = await Employee.create({
        empId: `VR-EMP-${String(seq).padStart(2, '0')}`,
        username, fullName
    });
    res.status(201).json(emp);
}));

// Admin can edit name, username and active status
app.patch('/api/employees/:id', auth(['admin']), wrap(async (req, res) => {
    const update = {};
    if (typeof req.body.active === 'boolean') update.active = req.body.active;
    if (req.body.fullName !== undefined) update.fullName = str(req.body.fullName, 60);
    if (req.body.username !== undefined) {
        const username = str(req.body.username, 30).toLowerCase();
        if (!USERNAME_RX.test(username)) throw httpErr(400, 'Username must be 3 to 30 characters: letters, numbers, _ . or -');
        if (await Employee.exists({ username, _id: { $ne: req.params.id } })) throw httpErr(409, 'That username is already taken.');
        update.username = username;
    }
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
/*  MASTER DATA (frames, products, passport, shoots, events)           */
/* ------------------------------------------------------------------ */
app.get('/api/master', auth(), wrap(async (_req, res) => {
    const [catalog, passports, shoots, events] = await Promise.all([
        Catalog.find().sort({ createdAt: 1 }),
        Passport.find().sort({ createdAt: 1 }),
        Shoot.find().sort({ createdAt: 1 }),
        Event.find().sort({ createdAt: 1 })
    ]);
    res.json({ catalog, passports, shoots, events });
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

// Edit the frame / product itself (name and category)
app.put('/api/catalog/:id', auth(['admin']), wrap(async (req, res) => {
    const item = await Catalog.findById(req.params.id);
    if (!item) throw httpErr(404, 'Item not found.');
    const name = str(req.body.name, 120);
    const category = str(req.body.category, 20);
    if (!name) throw httpErr(400, 'Name is required.');
    if (!['Frame', 'Product'].includes(category)) throw httpErr(400, 'Category must be Frame or Product.');
    const clash = await Catalog.exists({
        _id: { $ne: item._id }, category, name: new RegExp(`^${escapeRegex(name)}$`, 'i')
    });
    if (clash) throw httpErr(409, 'Another item with this name already exists in that category.');
    item.name = name;
    item.category = category;
    await item.save();
    res.json(item);
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

// Passport, shoots and events share one shape: [group] + name + price + details
function mountMaster(route, Model, groupField, allowedGroups) {
    const clean = body => {
        const o = { name: str(body.name, 120), price: num(body.price), details: str(body.details, 300) };
        if (groupField) {
            o[groupField] = str(body[groupField], 40);
            if (allowedGroups && !allowedGroups.includes(o[groupField])) throw httpErr(400, `${groupField} must be one of: ${allowedGroups.join(', ')}`);
            if (!o[groupField]) throw httpErr(400, 'Type, name and a valid price are required.');
        }
        if (!o.name || !(o.price >= 0)) throw httpErr(400, 'Name and a valid price are required.');
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
mountMaster('passports', Passport, null, null);
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

    const branch = str(b.branch, 20);
    if (!BRANCHES.includes(branch)) throw httpErr(400, 'Choose Branch 1 or Branch 2.');

    const items = (Array.isArray(b.items) ? b.items : []).slice(0, 100).map(i => ({
        title: str(i.title, 120), category: str(i.category, 60), details: str(i.details, 300), branch,
        qty: Math.floor(num(i.qty)), price: round2(num(i.price))
    }));
    if (!items.length || items.some(i => !i.title || !(i.qty >= 1 && i.qty <= 1000) || !(i.price >= 0))) {
        throw httpErr(400, 'The bill has an invalid item. Please check names, quantities and prices.');
    }

    // Totals are always calculated on the server.
    const subtotal = round2(items.reduce((s, i) => s + i.qty * i.price, 0));
    const discount = round2(Math.max(0, num(b.discount) || 0));
    if (discount > subtotal) throw httpErr(400, 'Discount cannot be more than the subtotal.');
    const total = round2(subtotal - discount);

    // Advance: the customer pays part now, the rest later. The bill stays out of sales until it is completed.
    const advance = round2(Math.max(0, num(b.advance) || 0));
    const isAdvance = advance > 0;
    if (isAdvance && advance >= total) {
        throw httpErr(400, 'Advance must be less than the bill total. For a full payment, leave the advance empty.');
    }
    const payNow = isAdvance ? advance : total;
    const pay = splitPayment(b, payNow);

    const seq = await nextSeq('bill');
    const date = parseDate(b.date) || todayStr();
    const bill = await Bill.create({
        billNo: formatBillNo(seq),
        date,
        orderDate: date,
        branch,
        status: isAdvance ? 'Advance' : 'Completed',
        // Biller comes from the login token, so it cannot be faked from the browser.
        billerUsername: req.user.username,
        billerEmpId: req.user.empId,
        billerName: req.user.name,
        client, items, subtotal, discount, total,
        paymentMode: pay.mode, cashAmount: pay.cash, gpayAmount: pay.gpay,
        advance: isAdvance ? advance : 0,
        advanceMode: isAdvance ? pay.mode : undefined,
        advanceCash: isAdvance ? pay.cash : 0,
        advanceGpay: isAdvance ? pay.gpay : 0,
        balance: isAdvance ? round2(total - advance) : 0,
        completedAt: isAdvance ? undefined : new Date(),
        completedBy: isAdvance ? undefined : req.user.username
    });
    res.status(201).json(bill);
}));

// Sales list: completed bills only. Advance orders live in /api/advances until they are paid in full.
app.get('/api/bills', auth(), wrap(async (req, res) => {
    const q = { status: { $ne: 'Advance' } };
    if (req.user.role !== 'admin') q.billerEmpId = req.user.empId;   // employees see only their own bills
    const { search, branch } = req.query;
    const range = dateRange(req.query);
    if (range) q.date = range;
    if (BRANCHES.includes(branch)) q.branch = branch;
    if (search) {
        const rx = new RegExp(escapeRegex(str(search, 60)), 'i');
        q.$or = [{ billNo: rx }, { 'client.name': rx }, { 'client.phone': rx }];
    }
    const limit = Math.min(parseInt(req.query.limit, 10) || 200, 1000);
    res.json(await Bill.find(q).sort({ createdAt: -1 }).limit(limit));
}));

// Advance orders waiting for the balance. Visible to every signed-in user so any counter can take the balance.
app.get('/api/advances', auth(), wrap(async (req, res) => {
    const q = { status: 'Advance' };
    if (req.query.search) {
        const rx = new RegExp(escapeRegex(str(req.query.search, 60)), 'i');
        q.$or = [{ billNo: rx }, { 'client.name': rx }, { 'client.phone': rx }];
    }
    res.json(await Bill.find(q).sort({ createdAt: -1 }).limit(500));
}));

// Customer pays the remaining balance: the bill moves to sales.
app.post('/api/bills/:id/complete', auth(), wrap(async (req, res) => {
    const bill = await Bill.findById(req.params.id);
    if (!bill) throw httpErr(404, 'Bill not found.');
    if (bill.status !== 'Advance') throw httpErr(409, 'This bill is already paid in full.');

    const balance = round2(bill.total - bill.advance);
    const pay = splitPayment(req.body || {}, balance);
    const cash = round2(bill.cashAmount + pay.cash);
    const gpay = round2(bill.gpayAmount + pay.gpay);

    const done = await Bill.findOneAndUpdate(
        { _id: bill._id, status: 'Advance' },
        { $set: {
            status: 'Completed',
            date: todayStr(),                       // sale is counted on the day it is paid in full
            balance,
            balanceMode: pay.mode, balanceCash: pay.cash, balanceGpay: pay.gpay,
            cashAmount: cash, gpayAmount: gpay,
            paymentMode: cash > 0 && gpay > 0 ? 'Mixed' : (cash > 0 ? 'Cash' : 'GPay'),
            completedAt: new Date(), completedBy: req.user.username
        } },
        { new: true }
    );
    if (!done) throw httpErr(409, 'This bill is already paid in full.');
    res.json(done);
}));

// Admin only: remove a pending advance order (for example a cancelled order).
app.delete('/api/advances/:id', auth(['admin']), wrap(async (req, res) => {
    const r = await Bill.deleteOne({ _id: req.params.id, status: 'Advance' });
    if (!r.deletedCount) throw httpErr(404, 'Advance order not found.');
    res.json({ ok: true });
}));

/* ------------------------------------------------------------------ */
/*  EXPENDITURE (admin only)                                           */
/* ------------------------------------------------------------------ */
app.get('/api/expenses', auth(['admin']), wrap(async (req, res) => {
    const q = {};
    const range = dateRange(req.query);
    if (range) q.date = range;
    const limit = Math.min(parseInt(req.query.limit, 10) || 100, 1000);
    res.json(await Expense.find(q).sort({ date: -1, createdAt: -1 }).limit(limit));
}));

app.post('/api/expenses', auth(['admin']), wrap(async (req, res) => {
    const amount = round2(num(req.body.amount));
    const note = str(req.body.note, 200);
    const branch = str(req.body.branch, 20) || 'General';
    const date = parseDate(req.body.date) || todayStr();
    if (!(amount > 0)) throw httpErr(400, 'Enter a valid expenditure amount.');
    if (!EXPENSE_BRANCHES.includes(branch)) throw httpErr(400, 'Choose General, Branch 1 or Branch 2.');
    res.status(201).json(await Expense.create({ date, amount, note, branch, createdBy: req.user.username }));
}));

app.delete('/api/expenses/:id', auth(['admin']), wrap(async (req, res) => {
    await Expense.findByIdAndDelete(req.params.id);
    res.json({ ok: true });
}));

/* ------------------------------------------------------------------ */
/*  STATS + CUSTOM REPORT (admin only)                                 */
/* ------------------------------------------------------------------ */
const SALES = { status: { $ne: 'Advance' } };   // completed bills only

app.get('/api/stats', auth(['admin']), wrap(async (_req, res) => {
    const today = todayStr();
    const group = { _id: null, revenue: { $sum: '$total' }, count: { $sum: 1 }, cash: { $sum: '$cashAmount' }, gpay: { $sum: '$gpayAmount' } };
    const branchGroup = { _id: { $ifNull: ['$branch', 'Branch 1'] }, revenue: { $sum: '$total' }, count: { $sum: 1 } };
    const expGroup = { _id: null, total: { $sum: '$amount' }, count: { $sum: 1 } };

    const [all] = await Bill.aggregate([{ $match: SALES }, { $group: group }]);
    const [todayAgg] = await Bill.aggregate([{ $match: { ...SALES, date: today } }, { $group: group }]);
    const byEmployee = await Bill.aggregate([
        { $match: SALES },
        { $group: { _id: '$billerEmpId', name: { $last: '$billerUsername' }, revenue: { $sum: '$total' }, count: { $sum: 1 } } },
        { $sort: { revenue: -1 } }
    ]);
    const branchAll = await Bill.aggregate([{ $match: SALES }, { $group: branchGroup }]);
    const branchToday = await Bill.aggregate([{ $match: { ...SALES, date: today } }, { $group: branchGroup }]);
    const [expAll] = await Expense.aggregate([{ $group: expGroup }]);
    const [expToday] = await Expense.aggregate([{ $match: { date: today } }, { $group: expGroup }]);
    const advancePending = await Bill.aggregate([
        { $match: { status: 'Advance' } },
        { $group: { _id: null, count: { $sum: 1 }, due: { $sum: '$balance' } } }
    ]);

    const empty = { revenue: 0, count: 0, cash: 0, gpay: 0 };
    res.json({
        all: all || empty,
        today: todayAgg || empty,
        byEmployee: byEmployee.map(e => ({ empId: e._id, name: e.name, revenue: e.revenue, count: e.count })),
        byBranch: BRANCHES.map(name => {
            const a = branchAll.find(x => x._id === name) || {};
            const t = branchToday.find(x => x._id === name) || {};
            return {
                branch: name,
                revenue: a.revenue || 0, count: a.count || 0,
                todayRevenue: t.revenue || 0, todayCount: t.count || 0
            };
        }),
        expenditure: {
            total: expAll?.total || 0, count: expAll?.count || 0,
            today: expToday?.total || 0, todayCount: expToday?.count || 0
        },
        advancePending: { count: advancePending[0]?.count || 0, due: advancePending[0]?.due || 0 },
        activeEmployees: await Employee.countDocuments({ active: true })
    });
}));

// Revenue and expenditure for any date range (and optional branch), shown separately.
app.get('/api/report', auth(['admin']), wrap(async (req, res) => {
    const range = dateRange(req.query);
    const branch = BRANCHES.includes(req.query.branch) ? req.query.branch : null;

    const billMatch = { ...SALES };
    const expMatch = {};
    if (range) { billMatch.date = range; expMatch.date = range; }
    if (branch) { billMatch.branch = branch; expMatch.branch = branch; }

    const [rev] = await Bill.aggregate([
        { $match: billMatch },
        { $group: { _id: null, revenue: { $sum: '$total' }, count: { $sum: 1 }, cash: { $sum: '$cashAmount' }, gpay: { $sum: '$gpayAmount' } } }
    ]);
    const [exp] = await Expense.aggregate([
        { $match: expMatch },
        { $group: { _id: null, total: { $sum: '$amount' }, count: { $sum: 1 } } }
    ]);
    const revenue = round2(rev?.revenue || 0);
    const expenditure = round2(exp?.total || 0);
    res.json({
        from: parseDate(req.query.from), to: parseDate(req.query.to), branch,
        revenue, count: rev?.count || 0, cash: round2(rev?.cash || 0), gpay: round2(rev?.gpay || 0),
        expenditure, expenseCount: exp?.count || 0,
        net: round2(revenue - expenditure)
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
