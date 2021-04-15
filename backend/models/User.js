import bcrypt from 'bcrypt'
import jwt from 'jsonwebtoken'
import mongoose from 'mongoose'

const UserSchema = new mongoose.Schema(
    {
        name: {
            type: String, 
            required: true
        },
        email: {
            type: String, 
            required: true, 
            unique: true,
            uniqueCaseInsensitive: true
        },
        password: {
            type: String,
            required: true,
            minLength: 6,
            select: false
        },
        address: {
            type: String,
        },
        location: {
            //GeoJSON Point
            type: {
                type: String,
                enum: ['Point']
            },
            coordinates: {
                type: [Number],
                index: '2dsphere'
            },
            formattedAddress: String,

        },
        role: {
            type: String,
            enum: ['user', 'admin'],
            default: 'user'
        },
        image: {
            type: String
        }
    },
    {
        timestamps: true
    }
)

UserSchema.pre('save', async function (next) {
    if (this.isModified('password')){
        const salt = await bcrypt.genSalt(10)
        this.password = await bcrypt.hash(this.password, salt)
    } else{
        next()
    }
})

UserSchema.methods.matchPassword = async function (password) {
    return await bcrypt.compare(password, this.password)
}

UserSchema.methods.getSignedJWTToken = function () {
    return jwt.sign({id: this._id}, process.env.JWT_SECRET, {
        expiresIn: process.env.JWT_EXPIRES
    })
}

const User = mongoose.model('User', UserSchema)
export default User