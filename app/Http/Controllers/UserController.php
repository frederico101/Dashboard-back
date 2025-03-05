<?php

namespace App\Http\Controllers\Api;

use App\Models\User;
use Illuminate\Http\Request;
use App\Http\Controllers\Controller;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Validator;
use Illuminate\Validation\ValidationException;

class UserController extends Controller
{
    /**
     * Get all users
     */
    public function index()
    {
        $users = User::all();
        return response()->json([
            'status' => 'success',
            'users' => $users
        ], 200);
    }

    /**
     * Get a single user by ID
     */
    public function show($id)
    {
        $user = User::findOrFail($id);
        return response()->json([
            'status' => 'success',
            'user' => $user
        ], 200);
    }

    /**
     * Create a new user
     */


    /**
     * User Login
     */
    //

    // public function login(Request $request)
    // {
    //     // Validate the incoming request
    //     $validator = Validator::make($request->all(), [
    //         'email' => 'required|email',
    //         'password' => 'required|string'
    //     ]);

    //     // Check if validation fails
    //     if ($validator->fails()) {
    //         return response()->json([
    //             'status' => 'error',
    //             'errors' => $validator->errors()
    //         ], 422);
    //     }

    //     // Check if the user exists and if the password is correct
    //     $user = User::where('email', $request->email)->first();

    //     if (!$user || !Hash::check($request->password, $user->password)) {
    //         return response()->json([
    //             'status' => 'error',
    //             'message' => 'Invalid login credentials'
    //         ], 401);
    //     }

    //     // Generate token using Sanctum
    //     $token = $user->createToken('auth_token')->plainTextToken;

    //     // Return successful login response with token
    //     return response()->json([
    //         'status' => 'success',
    //         'message' => 'Login successful',
    //         'user' => $user,
    //         'token' => $token
    //     ], 200);
    // }

    /**
     * User Logout
     */
    public function logout(Request $request)
    {
        // Revoke the token that was used to authenticate the current request
        $request->user()->currentAccessToken()->delete();

        return response()->json([
            'status' => 'success',
            'message' => 'Successfully logged out'
        ], 200);
    }

    /**
     * Update user profile
     */
    
}
