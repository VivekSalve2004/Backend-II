import { asyncHandler } from "../utils/asyncHandler.js";
import { ApiError } from "../utils/ApiError.js";
import { User } from "../models/user.model.js"; 
import { uploadOnCloudinary } from "../utils/Cloudinary.js";
import { ApiResponse } from "../utils/ApiResponse.js";
import jwt from "jsonwebtoken";

const generateAccessAndRefreshTokens = async(userId) => {
    try {
        const user = await User.findById(userId);
        const accessToken = user.generateAccessToken()
        const RefreshToken = user.generateRefreshToken()

        user.RefreshToken = RefreshToken
        await user.save({validateBeforeSave: false})

        return {accessToken, RefreshToken};



    } catch (error) {
        throw new ApiError(500 , "Something went wrongwhile generating refresh & access token ")
    }
}

const registerUser = asyncHandler(async (req , res) => {
    // get user details from frontend 
    // validation - not empty 
    // check if user already exists: uusername , email
    // check for images , check for avatar 
    // upload them to cloudinary , avatar
    // create user object - create entry in db
    // remove password & refresh token field from response
    // check for user creation

    const {fullname, email, username, password} = req.body
    // console.log("email: ",email);
    // console.log(req.body);
    
    // if(fullname === ""){
    //     throw new ApiError(400 , "Fullname is required")
    // }

    if( [fullname, email, username, password].some((field) => field?.trim() === "") )
    {
        throw new ApiError(400 , "All fields are required ")
    }

    const existedUser = await User.findOne({
        $or : [{ username } , { email }]
    })

    if(existedUser)
    {
        throw new ApiError(409 , "User already exists ")
    }

    const avatarLocalPath = req.files?.avatar?.[0]?.path;
    const coverImageLocalPath = req.files?.coverImage?.[0]?.path;
    
    // console.log(req.files);
    

    if(!avatarLocalPath){
        throw new ApiError(400 ,"Avatar file is required");
    }
    
    const avatar = await uploadOnCloudinary(avatarLocalPath);
    const coverImage = coverImageLocalPath ? await uploadOnCloudinary(coverImageLocalPath) : null;
    

    if(!avatar){
        throw new ApiError(500 , "Avatar upload failed ");
    }

    const user = await User.create({
        fullname,
        avatar: avatar.url,
        coverImage: coverImage?.url || "",
        email,
        password,
        username: username.toLowerCase()
    })

    const createdUser = await User.findById(user._id).select(
        "-password -refreshToken"
    );

    if(!createdUser)
    {
        throw new ApiError(500 , "Something went wrong while registering User ");
    }

    return res.status(201).json(
        new ApiResponse(200, createdUser , "User registered Successfully !!!")
    ); 
})

const loginUser = asyncHandler(async (req,res) => {
    // req body -> data
    // username or email
    // find the user 
    // password check 
    // access & refresh token 
    // send cookies
    
    const {email, username, password} = req.body

    if(!username && !email)
    {
        throw new ApiError(400 , "username or email is required ");
    }

    const user = await User.findOne({
        $or : [{username},{email}]
    });

    if(!user){
        throw new ApiError(404, "User does not exist ")
    }

    const isPasswordValid = await user.isPasswordCorrect(password);

    if(!isPasswordValid){
        throw new ApiError(401, "Invalid user credentials ")
    }

    const {accessToken , RefreshToken} = await generateAccessAndRefreshTokens(user._id);

    const loggedInUser = await User.findById(user._id).select("-password -refreshToken");

    // cookies
    const options = {       // read only not editable cookies 
        httpOnly: true,
        secure: true
    }

    return res
    .status(200)
    .cookie("accessToken" , accessToken , options)
    .cookie("RefreshToken" , RefreshToken, options)
    .json(
        new ApiResponse(
            200, 
            {
                user: loggedInUser, accessToken, RefreshToken
            },
            "User logged in Successfully !!!"
        )
    )
})

const logoutUser = asyncHandler(async(req,res) => {
    await User.findByIdAndUpdate(
        req.user._id,
        {
            $set: {
                refreshToken: undefined
            }
        },
        {
            new: true
        }
    )

    const options = {       // read only not editable cookies 
        httpOnly: true,
        secure: true
    }

    return res
    .status(200)
    .clearCookie("accessToken"  ,options)
    .clearCookie("RefreshToken" ,options)
    .json(new ApiResponse( 200, {} ,"User logged out Successfully !!!" ))

})

const refreshAccessToken = asyncHandler(async(req ,res) => {
    const incomingRefreshToken = req.cookies.refreshToken || req.body.refreshToken;

    if(incomingRefreshToken){
        throw new ApiError(401, "Unauthorized request ");
    }

   try {
     const decodedToken = jwt.verify(
         incomingRefreshToken,
         process.env.REFRESH_TOKEN_SECRET
     )
 
     const user = await User.findById(decodedToken?._id)
 
     if(!user){
         throw new ApiError(401, "Invalid Refresh Token");
     }
 
     if(incomingRefreshToken !== user?.refreshToken)
     {
         throw new ApiError(401, "Refresh token is expired or used ");
     }
 
     const options = {
         httpOnly: true,
         secure: true
     }
 
     const {accessToken, newrefreshToken} = await generateAccessAndRefreshTokens(user._id);
 
     return res
     .status(200)
     .cookie("accessToken" , accessToken , options)
     .cookie("refreshToken", newrefreshToken, options)
     .json(
         new ApiResponse(200 , {accessToken, refreshToken: newrefreshToken}, "Access token refreshed")
     )
 
   } 
   catch (error) {
        throw new ApiError(401, error?.message || "Invalid refresh token")
   }



});

export {
     registerUser,
     loginUser ,
     logoutUser,
     refreshAccessToken
}; 