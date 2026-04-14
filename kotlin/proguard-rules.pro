# teapod-tun2socks ProGuard / R8 rules
#
# These rules are included in the AAR and applied automatically to consuming apps.

# Сохранить все классы и методы gomobile-биндинга.
# gomobile генерирует Java-классы в пакете tun2socks.* — их нельзя обфусцировать,
# так как они вызываются через JNI по имени.
-keep class tun2socks.** { *; }

# Сохранить Kotlin-обёртки библиотеки.
-keep class com.teapodstream.tun2socks.** { *; }

# gomobile использует рефлексию для регистрации Go-объектов.
-keepclassmembers class * implements tun2socks.UIDValidatorFunc {
    public *;
}
