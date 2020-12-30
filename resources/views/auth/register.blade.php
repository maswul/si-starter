@extends('layouts.reg')

@section('content')
    <div class="card">
        <div class="card-body register-card-body">
            <p class="login-box-msg">Daftarkan User Baru!</p>

            <form action="{{ route('register') }}" method="post">
                @csrf
                <div class="input-group mb-3">
                    <input required type="text" id="name" name="name"
                           class="form-control @error('name') is-invalid @enderror" placeholder="Pegawai, ST">
                    <div class="input-group-append">
                        <div class="input-group-text">
                            <span class="fas fa-user"></span>
                        </div>
                    </div>

                    @error('name')
                    <span class="invalid-feedback" role="alert">
                                        <strong>{{ $message }}</strong>
                                    </span>
                    @enderror
                </div>
                <div class="input-group mb-3">
                    <input required type="text" id="nip" name="nip"
                           class="form-control @error('nip') is-invalid @enderror" placeholder="Nomor Induk Pegawai">
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
                    <input required type="text" id="noHP" name="noHP"
                           class="form-control @error('noHP') is-invalid @enderror"
                           placeholder="Nomor HP/WA">
                    <div class="input-group-append">
                        <div class="input-group-text">
                            <span class="fas fa-phone"></span>
                        </div>
                    </div>

                    @error('noHP')
                    <span class="invalid-feedback" role="alert">
                                        <strong>{{ $message }}</strong>
                                    </span>
                    @enderror
                </div>
                <div class="input-group mb-3">
                    <input type="password" id="password" name="password"
                           class="form-control @error('password') is-invalid @enderror"
                           placeholder="Password" required autocomplete="new-password">
                    <div class="input-group-append">
                        <div class="input-group-text">
                            <span class="fas fa-key"></span>
                        </div>
                    </div>

                    @error('password')
                    <span class="invalid-feedback" role="alert">
                                        <strong>{{ $message }}</strong>
                                    </span>
                    @enderror
                </div>
                <div class="input-group mb-3">
                    <input type="password" id="password-confirm" name="password_confirmation"
                           class="form-control @error('password-confirm') is-invalid @enderror"
                           placeholder="Retype Password" required autocomplete="new-password">
                    <div class="input-group-append">
                        <div class="input-group-text">
                            <span class="fas fa-key"></span>
                        </div>
                    </div>


                </div>


                <div class="row">

                    <!-- /.col -->
                    <div class="col-12">
                        <button type="submit" class="btn btn-primary btn-block">Register</button>
                    </div>
                    <!-- /.col -->
                </div>
            </form>

            <a href="{{ route('login') }}" class="text-center">Sudah punya Akun? Login!</a>
        </div>
        <!-- /.form-box -->
    </div><!-- /.card -->
@endsection
