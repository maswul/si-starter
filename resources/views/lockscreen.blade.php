<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <title>SPPDOnline | Lockscreen</title>
    <!-- Tell the browser to be responsive to screen width -->
    <meta name="viewport" content="width=device-width, initial-scale=1">


    <link rel="stylesheet" href="{{ asset('css/app.css') }}">

</head>
<body class="hold-transition lockscreen">
<!-- Automatic element centering -->
<div class="lockscreen-wrapper">
    <div class="lockscreen-logo">
        <a href="/home"><b>SPPD</b>.online</a>
    </div>
    <!-- User name -->
    <div class="lockscreen-name">{{ Auth::user()->name }}</div>

    <!-- START LOCK SCREEN ITEM -->
    <div class="lockscreen-item">
        <!-- lockscreen image -->
        <div class="lockscreen-image">
            <img src="{{ asset('img/nancy-crop.jpg') }}" alt="User Image">
        </div>
        <!-- /.lockscreen-image -->

        <!-- lockscreen credentials (contains the form) -->
        <form class="lockscreen-credentials" method="post" action="{{ route('login.unlock') }}">
            @csrf
            <div class="input-group">
                <input type="password" name="password" class="form-control" placeholder="password">

                <div class="input-group-append">
                    <button type="submit" class="btn"><i class="fas fa-arrow-right text-muted"></i></button>
                </div>


            </div>
        </form>


        <!-- /.lockscreen credentials -->

    </div>
    <!-- /.lockscreen-item -->
    <div class="help-block text-center">
        @if (session('errors'))
            {{ session('errors') }}
        @else
            Enter your password to retrieve your session
        @endif
    </div>
    <div class="text-center">
        <a href="{{ route('login.anotheruser') }}">Or sign in as a different user</a>
    </div>
    <div class="lockscreen-footer text-center">
        Copyright &copy; 2020-2021 <b><a href="#" class="text-black">SPPDOnline</a></b><br>
        All rights reserved
    </div>
</div>
<!-- /.center -->

<!-- jQuery -->
<script src="{{ asset('js/app.js') }}"></script>
</body>
</html>
