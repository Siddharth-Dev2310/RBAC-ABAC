import { asyncHandler } from "../utils/asyncHandler.utils.js";
import { ApiResponse } from "../utils/ApiResponse.utils.js";
import { User } from "../models/users.models.js";
import { ApiError } from "../utils/ApiError.utils.js";

const generateAccessAndRefreshTokens = async (userID) => {
  try {
    const user = await User.findById(userID);
    const accessToken = user.generateAccessToken();
    const refreshToken = user.generateRefreshToken();

    user.refreshToken = refreshToken;
    await user.save({ validateBeforeSave: false });

    return { accessToken, refreshToken };
  } catch (error) {
    throw new ApiError(500, "Error generating access and refresh tokens");
  }
};

let options = {
  httpOnly: true,
  secure: true,
};

const login = asyncHandler(async (req, res) => {
  const { username, email, password } = req.body;

  if (!username && !email) {
    return res
      .status(400)
      .json(new ApiResponse.error(res, 400, "Username or email is required"));
  }

  console.log(`password : ${password}`);
  

  // Validate user credentials
  const user = await User.findOne({
    $or: [{ username }, { email }],
  }).select("+password"); 

  if (!user) {
    throw new ApiError(400, "Can't Find User");
  }

  if (user.isActive) {
    throw new ApiError(403, "User account is inactive. Please contact support.");
  }

  user.isActive = true; // Set user as active on login
  await user.save({ validateBeforeSave: false });

  const isPasswordValid = await user.isPasswordCorrect(password);



  if (!isPasswordValid) {
    throw new ApiError(401, "Incorrect Password");
  }

  const { accessToken: token, refreshToken } =
    await generateAccessAndRefreshTokens(user._id);

  return res
    .status(200)
    .cookie("accessToken", token, options)
    .cookie("refreshToken", refreshToken, options)
    .json(
      new ApiResponse(200, 
        { 
          user: { 
            id: user._id, 
            email: user.email, 
            username: user.username 
          }, 
          accessToken: token, 
          refreshToken
        }, 
        "Login Successful"
      )
    );
});

const logout = asyncHandler(async (req, res) => {
  const userId = req.user._id;

  const user = await User.findById(userId);
  if (!user) {
    return res
      .status(404)
      .json(new ApiResponse.error(res, 404, "User not found"));
  }

  user.refreshToken = null;
  user.isActive = false; // Set user as inactive on logout
  await user.save({ validateBeforeSave: false });

  return res
    .status(200)
    .clearCookie("accessToken", options)
    .clearCookie("refreshToken", options)
    .json(
      new ApiResponse(200, 
        { 
          user: { 
            id: user._id, 
            email: user.email, 
            username: user.username 
          }

        }, 
        "Logout Successful"
      )
    );
});

export { login, logout };
