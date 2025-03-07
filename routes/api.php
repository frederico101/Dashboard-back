<?php

use Illuminate\Support\Facades\Route;
use App\Http\Controllers\UserController;

// Public routes
Route::prefix('users')->group(function () {
    Route::get('/hello', [UserController::class, 'sayHello']);
    Route::post('/register', [UserController::class, 'register']);
    Route::post('/login', [UserController::class, 'login'])->name('login');

    Route::post('/update', [UserController::class, 'update']);
    Route::post('/getbyemail', [UserController::class, 'getUserByEmail']);
});

// Protected routes (require authentication)
Route::middleware('auth:sanctum')->group(function () {
    Route::get('/', [UserController::class, 'index']);
    Route::get('/{id}', [UserController::class, 'show']);
    Route::put('/{id}', [UserController::class, 'update']);
    Route::delete('/{id}', [UserController::class, 'destroy']);
    Route::post('/logout', [UserController::class, 'logout']);
    Route::post('/protected', [UserController::class, 'protected']);
});

Route::middleware('auth:sanctum')->prefix('users')->group(function () {
    Route::get('/user', [UserController::class, 'getUser']);  // GET request for authenticated user
});
