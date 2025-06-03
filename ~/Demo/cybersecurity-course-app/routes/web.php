<?php

use App\Http\Controllers\CourseController;
use Illuminate\Support\Facades\Route;

Route::get('/', [CourseController::class, 'index'])->name('course.index');
Route::get('/guide', [CourseController::class, 'courseGuide'])->name('course.guide');
Route::get('/module/{module}', [CourseController::class, 'module'])->name('course.module');
Route::get('/lab/{lab}', [CourseController::class, 'lab'])->name('course.lab');
Route::get('/resources', [CourseController::class, 'resources'])->name('course.resources'); 