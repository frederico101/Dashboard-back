<?php

use Illuminate\Support\Facades\Route;
use App\Http\Controllers\HelloController;

// Public routes
Route::prefix('users')->group(function () {
    Route::get('/hello', [HelloController::class, 'sayHello']);
    Route::post('/register', [HelloController::class, 'register']);
    Route::post('/login', [HelloController::class, 'login'])->name('login');

    Route::post('/update', [HelloController::class, 'update']);
    Route::post('/getbyemail', [HelloController::class, 'getUserByEmail']);
});

// Protected routes (require authentication)
Route::middleware('auth:sanctum')->group(function () {
    Route::get('/', [HelloController::class, 'index']);
    Route::get('/{id}', [HelloController::class, 'show']);
    Route::put('/{id}', [HelloController::class, 'update']);
    Route::delete('/{id}', [HelloController::class, 'destroy']);
    Route::post('/logout', [HelloController::class, 'logout']);
    Route::post('/protected', [HelloController::class, 'protected']);
});

Route::middleware('auth:sanctum')->prefix('users')->group(function () {
    Route::get('/user', [HelloController::class, 'getUser']);  // GET request for authenticated user
});
