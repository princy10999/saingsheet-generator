<?php

namespace App\Http\Controllers\Api\Auth;

use Illuminate\Http\Request;
use App\Http\Controllers\Controller;
use App\Models\User;
use Illuminate\Support\Facades\Auth;
use Validator;
use App\Http\Controllers\API\BaseController as BaseController;
use Illuminate\Http\JsonResponse;
use Illuminate\Support\Facades\Mail;

class RegisterController extends BaseController
{
    public $successStatus = 200;
    /**
     * Register api
     *
     * @return \Illuminate\Http\Response
     */
    public function register(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'name' => 'required',
            'email' => 'required|email|unique:users,email',
            'password' => 'required',
            'c_password' => 'required|same:password',
        ]);

        if ($validator->fails()) {
            return $this->sendError('Validation Error.', $validator->errors());
        }

        $input = $request->all();
        $input['password'] = bcrypt($input['password']);
        $user = User::create($input);
        $success['token'] =  $user->createToken('WebiSheet')->accessToken;
        $success['user'] =  $user;

        return $this->sendResponse($success, 'User register successfully.');
    }

    /**
     * Login api
     *
     * @return \Illuminate\Http\Response
     */
    public function login(Request $request)
    {
        if (Auth::attempt(['email' => $request->email, 'password' => $request->password])) {
            $user = Auth::user();
            $success['token'] = $user->createToken('WebiSheet')->accessToken;
            $success['user'] =  $user;

            return $this->sendResponse($success, 'User login successfully.');
        } else {
            return $this->sendError('Unauthorised.', ['error' => 'Unauthorised']);
        }
    }
    /** 
     * details api 
     * 
     * @return \Illuminate\Http\Response 
     */

    public function sendOTP(Request $request)
    {
        try {
            $validator = Validator::make($request->all(), [
                'email' => 'required|email',
            ]);

            if ($validator->fails()) {
                return $this->sendError('Validation Error.', $validator->errors());
            }

            $email = $request->email;
            $data = User::where('email', $email)->first();
            if ($data) {
                $otp = random_int(100000, 999999);;
                User::where('email', $email)->update([
                    'otp' => $otp
                ]);
                $otpData['otp'] = $otp;
                Mail::send('emails.otp', $otpData, function ($message) use ($data) {
                    $message->to($data->email);
                    $message->subject('Password Reset Otp...');
                });
                return $this->sendResponse('false', 'Otp Has Been Sent Successfully...');
            } else {
                return $this->sendError('Not Found.', ['error' => 'Not Found This Email With Account Please Change Email.']);
            }
        } catch (\Throwable $th) {
            return $this->sendError('internal server error.', ['error' => 'server error...']);
        }
    }

    public function otpVerification(Request $request)
    {
        try {
            $validator = Validator::make($request->all(), [
                'otp' => 'required',
                'email' => 'required|email',
            ]);

            if ($validator->fails()) {
                return $this->sendError('Validation Error.', $validator->errors());
            }
            $otp = $request->otp;
            $email = $request->email;
            $user = User::where([['email', $email], ['otp', $otp]])->first();
            if ($user) {
                return $this->sendResponse($user->id, 'Otp Verification Successfully...');
            } else {
                return $this->sendError('failed.', ['error' => 'OTP is Incorrect...']);
            }
        } catch (\Throwable $th) {
            return $this->sendError('internal server error.', ['error' => 'server error...']);
        }
    }

    public function forgotPassword(Request $request)
    {
        try {
            $validator = Validator::make($request->all(), [
                'user_id' => 'required',
                'password' => 'required',
                'c_password' => 'required|same:password',
            ]);

            if ($validator->fails()) {
                return $this->sendError('Validation Error.', $validator->errors());
            }
            $input = $request->all();
            $data['password'] = bcrypt($input['password']);
            $user = User::where('id', $input['user_id'])->update($data);
            if ($user == 1) {
                return $this->sendResponse('success', 'Password Reset Successfully...');
            } else {
                return $this->sendError('failed.', ['error' => 'password Reset Failed...']);
            }
        } catch (\Throwable $th) {
            return $this->sendError('internal server error.', ['error' => 'server error...']);
        }
    }
    public function details()
    {
        $user = Auth::user();
        return response()->json(['success' => $user], $this->successStatus);
    }
    public function social_login(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'email' => 'required|email',
        ]);
        if ($validator->fails()) {
            return response()->json(['error'=>$validator->errors()], 401);
        }
        $input = $request->all();
        $user = User::where('email',$input['email'])->first();
        if($user){
            $success['token'] =  $user->createToken('WebiSheet')->accessToken;
            $success['users'] =  $user;
            return response()->json(['success' => $success], $this->successStatus);
        }else{
        
            $user = User::create($input);
            $success['token'] =  $user->createToken('WebiSheet')->accessToken;
            $success['name'] =  $user;
            return response()->json(['success' => $success], $this->successStatus);
        }
    }
    public function logout()
    {
        // User::where('id',$id)->delete();
        // return response()->json([
        //     'message' => 'User Deleted'
        // ]);
        $user = Auth::user()->token();
        $user->revoke();
        $success['users'] =  $user;
        $success['message'] =  'User logout successfully.';
        return response()->json(['success' => $success], $this->successStatus);
    }
}