const catchError = require('../utils/catchError');
const User = require('../models/User');
const bcrypt= require('bcrypt');
const sendEmail= require('../utils/sendEmail');
const EmailCode= require('../models/EmailCode');
const jwt = require('jsonwebtoken');

const getAll = catchError(async(req, res) => {
    const results = await User.findAll();
    return res.json(results);
});

const create = catchError(async(req, res) => {
    const {email, password, firstName, lastName, country, image, frontBaseUrl }= req.body;
    const encriptedPassword= await bcrypt.hash(password, 10);
    const result = await User.create({
        email,
        password: encriptedPassword,
        firstName,
        lastName,
        country,
        image,
    });

    const code = require('crypto').randomBytes(32).toString("hex");
    const link = `${frontBaseUrl}/auth/verify_email/${code}`;
    await EmailCode.create({
        code,
        userId: result.id
    })

    await sendEmail({
        to: email,
        subject: 'Email de verificación',
        html:`
            <h1>Hola ${firstName}</h1>
            <p>Gracias por iniciar session</p>
            <b>Link para verificar su correo: ${link}</b>
        `,
    });
    return res.status(201).json(result);
});

const resetPassword = catchError(async(req, res)=>{
    const { email, frontBaseUrl}= req.body;
    const user = await User.findOne({where: {email:email}});
    if (!user) return res.status(401).json({message: "Email no registrado"});
    const code = require('crypto').randomBytes(32).toString("hex");
    const link = `${frontBaseUrl}/auth/reset_password/${code}`;
    await EmailCode.create({
        code,
        userId: user.id
    })

    await sendEmail({
        to: email,
        subject: 'Email de verificación',
        html:`
            <h1>Hola ususario</h1>
            <b>Este es el link para cambiar su contraseña: ${link}</b>
        `,
    });
    return res.status(201).json(user);
});

const getOne = catchError(async(req, res) => {
    const { id } = req.params;
    const result = await User.findByPk(id);
    if(!result) return res.sendStatus(404);
    return res.json(result);
});

const remove = catchError(async(req, res) => {
    const { id } = req.params;
    await User.destroy({ where: {id} });
    return res.sendStatus(204);
});

const update = catchError(async(req, res) => {
    const { id } = req.params;
    const result = await User.update(
        req.body,
        { where: {id}, returning: true }
    );
    if(result[0] === 0) return res.sendStatus(404);
    return res.json(result[1][0]);
});

const verifyCode= catchError(async(req, res)=>{
    const {code }=req.params;
    const emailCode= await EmailCode.findOne({where:{code: code}});
    if(!emailCode) return res.status(401).json({message:"Código inválido"});
    const user = await User.findByPk(emailCode.userId);
    user.isVerified = true;
    await user.save();
    await emailCode.destroy();
    return res.json(user);
});

const login = catchError(async(req, res)=>{
    const {email, password}= req.body;
    const user = await User.findOne({where: {email}});
    if(!user) return res.status(401).json({message: "Invalid credentials"});
    if(user.isVerified=== false) return res.status(401).json({message: "Invalid email"});
    const isValid= await bcrypt.compare(password, user.password);
    if(!isValid)return res.status(401).json({message: "Invalid credentials"});

    const token = jwt.sign(
        {user },
        process.env.TOKEN_SECRET,
        {expiresIn:"1d"});
    
    return res.json({user, token});
});

const getLoggedUser= catchError(async(req, res)=>{
    const user = req.user;
    return res.json(user)
});

const verifyCodeRessetPassword= catchError(async(req, res)=>{
    const {code}= req.params;
    const emailCode= await EmailCode.findOne({where:{code: code}});
    if(!emailCode) return res.status(401).json({message:"Código inválido"});
    const user = await User.findByPk(emailCode.userId);
    const {password}= req.body;
    const encriptedPassword= await bcrypt.hash(password, 10);
    user.password= encriptedPassword;
    await user.save();
    await emailCode.destroy();
    return res.json(user);
});

module.exports = {
    getAll,
    create,
    getOne,
    remove,
    update,
    verifyCode,
    login,
    getLoggedUser, 
    resetPassword,
    verifyCodeRessetPassword
}