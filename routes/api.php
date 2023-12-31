<?php

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;

/*
|--------------------------------------------------------------------------
| API Routes
|--------------------------------------------------------------------------
|
| Here is where you can register API routes for your application. These
| routes are loaded by the RouteServiceProvider within a group which
| is assigned the "api" middleware group. Enjoy building your API!
|
*/

Route::middleware('auth:sanctum')->get('/user', function (Request $request) {
    return $request->user();
});
Route::post('login', [App\Http\Controllers\Api\Auth\RegisterController::class, 'login']);
Route::post('register', [App\Http\Controllers\Api\Auth\RegisterController::class, 'register']);
Route::post('/social-login', [App\Http\Controllers\Api\Auth\RegisterController::class, 'social_login']);
Route::post('send-otp', [App\Http\Controllers\Api\Auth\RegisterController::class, 'sendOTP']);
Route::post('otp-verification', [App\Http\Controllers\Api\Auth\RegisterController::class, 'otpVerification']);
Route::post('reset-password', [App\Http\Controllers\Api\Auth\RegisterController::class, 'forgotPassword']);


Route::group(['middleware' => 'auth:api'], function () {
    Route::post('logout', [App\Http\Controllers\Api\Auth\RegisterController::class, 'logout']);
    Route::post('details', [App\Http\Controllers\Api\Auth\RegisterController::class, 'details']);
});