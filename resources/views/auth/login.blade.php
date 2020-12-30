@extends('layouts.guest')
@section('content')
    <div class="card card-outline card-primary">
        <div class="card-header text-center">
            <a class="h1" href="/home"><b>SPPD</b>online</a>
        </div>
        <div class="card-body">
            <p class="login-box-msg">Silahkan masuk terlebih dahulu</p>

            <form action="{{ route('login') }}" method="post">
                @csrf
                <div class="input-group mb-3">
                    <input type="text" id="nip" name="nip" class="form-control @error('nip') is-invalid @enderror" placeholder="Nomor Induk Pegawai">
                    <div class="input-group-append">
                        <div class="input-group-text">
                            <span class="fas fa-sort-numeric-down"></span>
                        </div>
                    </div>
                    @error('nip')
                    <span class="invalid-feedback" role="alert">
                                        <strong>{{ $message }}</strong>
                                    </span>
                    @enderror
                </div>
                <div class="input-group mb-3">
                    <input type="password" name="password" id="password" class="form-control @error('password') is-invalid @enderror" placeholder="Password">
                    <div class="input-group-append">
                        <div class="input-group-text">
                            <span class="fas fa-lock"></span>
                        </div>
                    </div>
                    @error('password')
                    <span class="invalid-feedback" role="alert">
                                        <strong>{{ $message }}</strong>
                                    </span>
                    @enderror
                </div>
                <div class="row">
                    <div class="col-8">
                        <div class="icheck-primary">
                            <input type="checkbox" name="remember" id="remember" {{ old('remember') ? 'checked' : '' }}>
                            <label for="remember">
                                Ingat saya
                            </label>
                        </div>
                    </div>
                    <!-- /.col -->
                    <div class="col-4">
                        <button type="submit" class="btn btn-primary btn-block">Sign In</button>
                    </div>
                    <!-- /.col -->
                </div>
            </form>

        </div>
        <!-- /.card-body -->
    </div>
    <!-- /.card -->
@endsection
