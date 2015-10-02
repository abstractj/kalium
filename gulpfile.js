var gulp = require('gulp'),
    uglify = require('gulp-uglify'),
    less = require('gulp-less'),
    plumber = require('gulp-plumber'),
    browserSync = require('browser-sync'),
    reload = browserSync.reload;

// Uglyfies js on to /js/minjs
gulp.task('scripts', function(){  
  gulp.src('js/*.js')
    .pipe(plumber())
    .pipe(uglify())
    .pipe(gulp.dest("js/minjs"));
}); 

// Compiles less on to /css
gulp.task('less', function () {
  gulp.src('less/**/*.less')
   .pipe(plumber())
   .pipe(less())
   .pipe(gulp.dest('css'))
   .pipe(reload({stream:true}));
});

// reload server
gulp.task('browser-sync', function() {
    browserSync({
        server: {
            baseDir: "./"
        }
    });
});

// Reload all Browsers
gulp.task('bs-reload', function () {
    browserSync.reload();
});

// watch for changes on files
gulp.task('watch', function(){ 
  gulp.watch('js/*.js', ['scripts']);
  gulp.watch('less/*.less', ['less']);
  gulp.watch("*.html", ['bs-reload']);
}); 

// deploys
gulp.task('default',  ['scripts', 'less','browser-sync','watch']);