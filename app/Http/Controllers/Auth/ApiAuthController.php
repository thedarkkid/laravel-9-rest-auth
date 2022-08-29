<?php

namespace App\Http\Controllers\Auth;

use App\Http\Controllers\Controller;
use App\Models\User;
use Illuminate\Contracts\Foundation\Application;
use Illuminate\Contracts\Routing\ResponseFactory;
use Illuminate\Http\Request;
use Illuminate\Http\Response;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Validator;
use Illuminate\Support\Str;

class ApiAuthController extends Controller
{
    const TOKEN_NAME = 'Laravel Password Grant Client';

    /**
     * Registers user by name email, password;
     * @param Request $request
     * @return Application|ResponseFactory|Response
     */
    public function register(Request $request): Response|Application|ResponseFactory
    {
        $validator = Validator::make($request->all(), [
            'name' => 'required|string|max:255',
            'email' => 'required|string|email|max:255|unique:users',
            'password' => 'required|string|min:6|confirmed',
        ]);
        if ($validator->fails()) {
            return response(['errors' => $validator->errors()->all()], 422);
        }
        $request['password'] = Hash::make($request->input('password'));
        $request['remember_token'] = Str::random(10);
        $user = User::create($request->toArray());
        $token = $user->createToken(self::TOKEN_NAME)->accessToken;
        $response = ['token' => $token];
        return response($response, 200);
    }

    /**
     * Returns an authorization token on successful user authentication.
     * @param Request $request
     * @return Application|ResponseFactory|Response
     */
    public function login(Request $request): Response|Application|ResponseFactory
    {
        $validator = Validator::make($request->all(), [
            'email' => 'required|string|email|max:255',
            'password' => 'required|string|min:6|confirmed',
        ]);
        if ($validator->fails()) {
            return response(['errors' => $validator->errors()->all()], 422);
        }

        $user = User::where('email', $request->input('email'))->first();
        if (!$user || !Hash::check($request->input('password'), $user->password)) {
            $response = ["errors" => ["message" => 'email or password incorrect']];
            return response($response, 422);
        }

        $token = $user->createToken(self::TOKEN_NAME)->accessToken;
        $response = ['token' => $token];
        return response($response, 200);
    }

    /**
     * Revokes authorization token.
     * @param Request $request
     * @return Response|Application|ResponseFactory
     */
    public function logout (Request $request): Response|Application|ResponseFactory
    {
        $token = $request->user()->token();
        $token->revoke();
        $response = ['message' => 'You have been successfully logged out!'];
        return response($response, 200);
    }


}
