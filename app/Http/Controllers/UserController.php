<?php

namespace App\Http\Controllers;

use App\Models\User;
use Illuminate\Http\Request;
use App\Http\Controllers\Controller;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Validator;
use Illuminate\Validation\ValidationException;

class UserController extends Controller
{
    public function sayHello()
    {
        return response()->json([
            'message' => 'Hello, world!'
        ]);
    }

    public function verifyToken(Request $request)
    {
        $user = Auth::user(); // Get the authenticated user

        if ($user) {
            return response()->json([
                'id' => $user->id,
                'name' => $user->name,
                'email' => $user->email,
                'role' => $user->role, // Make sure the role is included
                'email_verified_at' => $user->email_verified_at,
                'created_at' => $user->created_at,
                'updated_at' => $user->updated_at,
            ]);
        }

        return response()->json(['message' => 'Unauthorized'], 401);
    }

    public function getUser(Request $request)
    {
        return response()->json($request->user());
    }

     public function getUserByEmail(Request $request)
    {
        $email = $request->input('email'); // Get email from query parameters

        $user = User::where('email', $email)->first();

        if (!$user) {
            return response()->json([
                'status' => 'error',
                'message' => 'User not found'
            ], 404);
        }

        return response()->json([
            'status' => 'success',
            'data' => $user
        ], 200);
    }

    public function logout(Request $request)
    {
        // Revoke the token that was used to authenticate the current request
        $request->user()->currentAccessToken()->delete();

        return response()->json([
            'status' => 'success',
            'message' => 'Successfully logged out'
        ], 200);
    }


    public function login(Request $request)
    {
        // Validate the incoming request
        $validator = Validator::make($request->all(), [
            'email' => 'required|email',
            'password' => 'required|string'
        ]);

        // Check if validation fails
        if ($validator->fails()) {
            return response()->json([
                'status' => 'error',
                'errors' => $validator->errors()
            ], 422);
        }

        // Check if the user exists and if the password is correct
        $user = User::where('email', $request->email)->first();

        if (!$user || !Hash::check($request->password, $user->password)) {
            return response()->json([
                'status' => 'error',
                'message' => 'Invalid login credentials'
            ], 401);
        }

        // Generate token using Sanctum
        $token = $user->createToken('auth_token')->plainTextToken;

        // Return successful login response with token
        return response()->json([
            'status' => 'success',
            'message' => 'Login successful',
            'user' => $user,
            'token' => $token
        ], 200);
    }

    // public function protected(Request $request)
    // {
    //     try {
    //         $user = $request->user();
    //         return response()->json(['user' => $user]);
    //     } catch (\Exception $e) {
    //         return response()->json(['error' => 'Token is invalid or expired'], 401);
    //     }
    // }

    public function protected(Request $request)
    {
        try {
            $user = $request->user(); // Get authenticated user

            // Return both user data and role
            return response()->json([
                'user' => $user, // Return the user data
                'role' => $user->role // Explicitly return the role field
            ]);
        } catch (\Exception $e) {
            return response()->json(['error' => 'Token is invalid or expired'], 401);
        }
    }

    public function register(Request $request)
    {
        // Validate input
        $validator = Validator::make($request->all(), [
            'name' => 'required|string|max:255',
            'email' => 'required|string|email|unique:users,email',
            'password' => 'required|string|min:2'
        ]);

        // Check validation
        if ($validator->fails()) {
            return response()->json([
                'status' => 'error',
                'errors' => $validator->errors()
            ], 422);
        }

        // Determine the role based on the email
        $email = $request->email;
        $role = (strpos($email, 'admin') !== false) ? 'admin' : 'user'; // Check if "admin" exists in the email

        // Create user with assigned role
        $user = User::create([
            'name' => $request->name,
            'email' => $email,
            'password' => Hash::make($request->password),
            'role' => $role // Assign role here
        ]);

        // Generate token
        $token = $user->createToken('auth_token')->plainTextToken;

        return response()->json([
            'status' => 'success',
            'message' => 'User created successfully',
            'user' => $user,
            'role' => $role,
            'token' => $token
        ], 201);
    }


    // public function register(Request $request)
    // {
    //     // Validate input
    //     $validator = Validator::make($request->all(), [
    //         'name' => 'required|string|max:255',
    //         'email' => 'required|string|email|unique:users,email',
    //         'password' => 'required|string|min:2'
    //     ]);

    //     // Check validation
    //     if ($validator->fails()) {
    //         return response()->json([
    //             'status' => 'error',
    //             'errors' => $validator->errors()
    //         ], 422);
    //     }

    //     // Create user
    //     $user = User::create([
    //         'name' => $request->name,
    //         'email' => $request->email,
    //         'password' => Hash::make($request->password)
    //     ]);

    //     // Generate token
    //     $token = $user->createToken('auth_token')->plainTextToken;

    //     return response()->json([
    //         'status' => 'success',
    //         'message' => 'User created successfully',
    //         'user' => $user,
    //         'token' => $token
    //     ], 201);
    // }

    public function update(Request $request, $id)
    {
        $user = User::findOrFail($id);

        $validator = Validator::make($request->all(), [
            'name' => 'sometimes|string|max:255',
            'email' => 'sometimes|string|email|unique:users,email,'.$user->id,
            'password' => 'sometimes|string|min:8|confirmed'
        ]);

        if ($validator->fails()) {
            return response()->json([
                'status' => 'error',
                'errors' => $validator->errors()
            ], 422);
        }

        // Update fields if provided
        if ($request->has('name')) {
            $user->name = $request->name;
        }

        if ($request->has('email')) {
            $user->email = $request->email;
        }

        if ($request->has('password')) {
            $user->password = Hash::make($request->password);
        }

        $user->save();

        return response()->json([
            'status' => 'success',
            'message' => 'User updated successfully',
            'user' => $user
        ], 200);
    }

    /**
     * Delete user
     */
    public function destroy($id)
    {
        $user = User::findOrFail($id);
        $user->delete();

        return response()->json([
            'status' => 'success',
            'message' => 'User deleted successfully'
        ], 200);
    }
}

