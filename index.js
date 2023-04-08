import express from "express";
import path from 'path';
import mongoose from 'mongoose';
import cookieParser from "cookie-parser"
import jwt from "jsonwebtoken";
import bcrypt from "bcrypt";

mongoose.connect("mongodb://localhost:27017", {
    dbname:"backend"})
.then(()=>console.log("Database Connected"))
.catch((err)=>console.log(err))

const userSchema = new mongoose.Schema({
    name: String,
    email: String,
    password:String,
})
const User = mongoose.model("User", userSchema);
const app = express();
app.set("view engine", "ejs");

//using middlewares
app.use(express.static(path.join(path.resolve(), "public")));
app.use(express.urlencoded({extended:true}));
app.use(cookieParser()); 

const isAuth = async (req,res,next)=>{
    const {token}= req.cookies;
    if(token){
        const decoded=jwt.verify(token,"secret-key")
        req.user = await User.findById(decoded._id)
        next()
    }
    else{
        res.render("login");
    }
    }
app.get("/",isAuth,(req,res)=>{
    console.log(req.user)
    res.render("logout", {name:req.user.name});
} )
app.get("/register", async (req,res)=>{
    res.render("register")
})
app.post("/login", async (req,res)=>{
    const {email,password}= req.body;
    let user = await User.findOne({email})
    if(!user) return res.redirect("/register");
    const isMatch=await bcrypt.compare(password,user.password);
    if(!isMatch)return res.render("login", {email,message:"Incorrect Password"});
    
    const token = jwt.sign({_id:user._id}, "secret-key")

    res.cookie("token",token,{
        httpOnly:true,expires:new Date(Date.now()+60*1000)
    });
    res.redirect("/");
})
app.post("/register", async (req,res)=>{
    const {name, email,password}= req.body;
    let user = await User.findOne({email})
    if(user){
        return res.redirect("/login");
    }
    const hashedPass=await bcrypt.hash(password,10);
    user =await User.create({name,email,password:hashedPass});
    const token = jwt.sign({_id:user._id}, "secret-key")

    res.cookie("token",token,{
        httpOnly:true,expires:new Date(Date.now()+60*1000)
    });
    res.redirect("/");
})
app.get("/logout", (req,res)=>{
    res.cookie("token",null,{
        httpOnly:true,expires:new Date(Date.now())
    });
    res.redirect("/");
})


app.listen(5000,()=>{
    console.log("Server is working")
})