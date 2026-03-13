require("dotenv").config();

const express = require("express");
const session = require("express-session");
const mongoose = require("mongoose");
const path = require("path");

const multer = require("multer");
const sharp = require("sharp");
const fs = require("fs");

const storage = multer.memoryStorage();

const upload = multer({
    storage: storage

});


const app = express();


app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(__dirname));
app.use("/bills", express.static("public/bills"));


app.use("/uploads", express.static("public/uploads"));
app.use(express.static("public"));
app.use(session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
}));



// 🔥 MongoDB Connect
mongoose.connect(process.env.MONGO_URI)
.then(() => console.log("MongoDB Connected"))
.catch(err => console.log(err));

// 🔥 Bill Schema
const billSchema = new mongoose.Schema({
    billNumber: String,
    name: String,
    mobile: String,
    total: Number,
    received: Number,
    image: String,
    date: { type: Date, default: Date.now }
});

const Bill = mongoose.model("Bill", billSchema);


// PRODUCT SCHEMA
const productSchema = new mongoose.Schema({
    name: String,
    price: Number,
    image: String
});

const Product = mongoose.model("Product", productSchema);





// HOME
app.get("/", (req, res) => {
    res.sendFile(path.join(__dirname, "index.html"));
});

// CONTROLER
app.get("/controler", (req, res) => {
    res.sendFile(path.join(__dirname, "controler.html"));
});

// ADMIN LOGIN
app.get("/adminuser", (req, res) => {
    res.sendFile(path.join(__dirname, "adminuser.html"));
});

app.get("/nwork", (req, res) => {
    res.sendFile(path.join(__dirname, "nwork.html"));
});

app.get("/admin-bill", (req, res) => {
    res.sendFile(path.join(__dirname, "admin-bill.html"));
});

app.post("/login", (req, res) => {

    if (
        req.body.username === process.env.ADMIN_USER &&
        req.body.password === process.env.ADMIN_PASS
    ) {
        req.session.loggedIn = true;
        return res.json({ success: true });
    }

    res.json({ success: false });
});

// PROTECTED ADMIN
app.get("/admin", (req, res) => {
    if (!req.session.loggedIn) {
        return res.redirect("/adminuser");
    }
    res.sendFile(path.join(__dirname, "admin.html"));
});

// PROTECTED ADMIN
app.get("/product-admin", (req, res) => {
    if (!req.session.loggedIn) {
        return res.redirect("/adminuser");
    }
    res.sendFile(path.join(__dirname, "product-admin.html"));
});

// 🔥 SAVE BILL API
app.post("/save-bill", async (req, res) => {

    if (!req.session.loggedIn) return res.status(401).json({ error: "Unauthorized" });

    const bill = new Bill(req.body);
    await bill.save();

    res.json({ success: true });
});

// 🔥 GET ALL BILLS
app.get("/get-bills", async (req, res) => {

    if (!req.session.loggedIn) return res.status(401).json({ error: "Unauthorized" });

    const bills = await Bill.find().sort({ date: -1 });
    res.json(bills);
});
// 🔥 UPDATE BILL
app.put("/update-bill/:id", async (req, res) => {

    if (!req.session.loggedIn)
        return res.status(401).json({ error: "Unauthorized" });

    await Bill.findByIdAndUpdate(req.params.id, req.body);
    res.json({ success: true });
});

// 🔥 DELETE BILL
app.delete("/delete-bill/:id", async (req, res) => {

    if (!req.session.loggedIn)
        return res.status(401).json({ error: "Unauthorized" });

    await Bill.findByIdAndDelete(req.params.id);
    res.json({ success: true });
});

app.get("/product-admin", (req, res) => {

    res.sendFile(path.join(__dirname, "product-admin.html"));
});



app.get("/api/products", async (req, res) => {
    
        const products = await Product.find();
        res.json(products);
    
});


app.post("/api/add-product", async (req,res)=>{
    try {
    const {name,price,image} = req.body;

    const product = new Product({
        name,
        price,
        image
    });

    await product.save();
    res.json({message:"Product Added"});
}catch(err){
    console.log(err);
    res.status(500).json({message:"Server Error"});
}
});


app.delete("/api/delete-product/:id", async (req,res)=>{
    

    await Product.findByIdAndDelete(req.params.id);
    res.json({message:"Product Deleted"});
});


app.put("/api/update-product/:id", async (req,res)=>{
    const {name,price,image} = req.body;

    await Product.findByIdAndUpdate(req.params.id,{
        name,
        price,
        image
    });

    res.json({message:"Product Updated"});
});


app.post("/upload-image", upload.single("image"), async (req,res)=>{
try {

if(!req.file){ return res.status(400).json({message:"No file uploaded"});    

}
const filename = Date.now()+".jpg";

await sharp(req.file.buffer)
.resize(800)
.jpeg({quality:70})
.toFile("public/uploads/"+filename);

res.json({
image:"/uploads/"+filename
});

}catch(err){
    console.log(err);
    res.status(500).json({message:"image upload failed"});
}
});





app.post("/customer/check-bill", async (req, res) => {

const {billNumber, mobile} = req.body;
const bill = await Bill.findOne({
    billNumber:billNumber,
     mobile:mobile
});

if(bill){
    res.json({success:true,
         image:bill.image
        });
}else{
    res.json({success:false});  

}
});


app.get("/admin/bills", async (req, res) => {
    const bills = await Bill.find().sort({ date: -1 });
    res.json(bills);
});


app.post("/admin/upload-bill", upload.single("image"), async (req,res)=>{

const {mobile,billNumber} = req.body;
const filename = Date.now()+".jpg";

await sharp(req.file.buffer)
.resize(800)
.jpeg({quality:70})
.toFile("public/bills/"+filename);
const newBill = new Bill({

mobile,
billNumber,
image:filename

});

await newBill.save();

res.json({status:"success"});

});


app.delete("/admin/delete-bill/:id", async (req,res)=>{

await Bill.findByIdAndDelete(req.params.id);
res.json({status:"deleted"});
});


app.put("/admin/update-bill/:id", async (req,res)=>{
const {mobile,billNumber} = req.body;

await Bill.findByIdAndUpdate(req.params.id,{
mobile,
billNumber
});
res.json({status:"updated"});

});



app.listen(3000, () => console.log("Server Running..."));
