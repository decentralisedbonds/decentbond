#include <jni.h>
#include <string>

int g_myCounter = 0;

extern "C"
jstring
Java_com_example_decentbond_MainActivity_stringFromJNI(JNIEnv* env, jobject) {
    return env->NewStringUTF("hello from c++");
}

extern "C" {
void
Java_com_example_decentbond_MainActivity_setMyCounter(JNIEnv*, jobject, jint value) {
    g_myCounter = value;
}

jint
Java_com_example_decentbond_MainActivity_getMyCounter(JNIEnv*, jobject) {
    return g_myCounter;
}
}

