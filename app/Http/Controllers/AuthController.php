<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;
use App\Models\User;

class AuthController extends Controller
{   
    #Registrar usuário
    public function register(Request $request){
        $request->validate([
            'name' => 'required|string',
            'email' => 'required|string|unique:users,email',
            'password' => 'required|string|confirmed'
        ]);

        $user = User::create([
            'name' => $request->name,
            'email' => $request->email,
            'password' => bcrypt($request->password)
        ]);

        $token = $user->createToken('primeirotoken')->plainTextToken;

        $response = [
            'user' => $user,
            'token' => $token
        ];

        return response($response, 201);
    }
    
    #Login do usuario
    public function login(Request $request){
        #validando se o emial e a senha foram informados
        $request->validate([
            'email' => 'required|string',
            'password' => 'required|string'
        ]);

        #checar o email do usuario
        $user = User::where('email', $request->email)->first();

        #valida o usuario e checa o password

        if(!$user || !Hash::check($request->password, $user->password)){
            return response([
                'message' => 'credenciais invalidas'
            ], 401);
        }

        $token = $user->createToken('primeirotoken')->plainTextToken;

        $response = [
            'user' => $user,
            'token' => $token
        ];
        
        return response($response, 201);

    }

    public function logout(){
        auth()->user()->tokens()->delete();

        return [
            'message' => 'Logout efetuado com sucesso e exclusão dos tokens.'
        ];

    }

}
