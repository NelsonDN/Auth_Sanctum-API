<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Http\Response;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Auth;
use App\Models\User;


class AuthController extends Controller
{
    //
    public function welcome()
    {
        if (auth('sanctum')->check()){
            
            return "Bienvenue " .auth('sanctum')->user()->name;
        }else {
            return response([
                'message' => "Bienvenue .... Vous n'êtes pas authentifié"
            ]);
        }
    }

    public function register(Request $request)
    {
        $request->validate([
            'name' => ['required', 'string'],
            'email' => ['required', 'string', 'unique:users,email'],
            'password' => ['required', 'string', 'confirmed']
        ]);

        $user = User::create([
            'name' => $request->name,
            'email' => $request->email,
            'password' => bcrypt($request->password)
        ]);

        $token = $user->createToken('myapptoken')->plainTextToken;

        return response([
            'Users' => $user,
            'Token' => $token
        ], 201);
    }

    public function login(Request $request)
    {
        $request->validate([
            'email' => ['required', 'string'],
            'password' => ['required', 'string']
        ]);

        // Vérifier l'email
        $user = User::where('email', $request->email)->first();

        // Vérifier le mot de passe
        if (!$user || !Hash::check($request->password, $user->password))
        {
            return response([
                'message' => 'aucun compte existant'
            ], 401);
        }

        $token = $user->createToken('myapptoken')->plainTextToken;

        return response()->json([
            'Users' => $user,
            'Token' => $token
        ]);
    }

    public function logout(){
        auth()->user()->tokens()->delete();

        return response([
            'message' => 'Vous êtes déconnecté'
        ]);
    }


}
