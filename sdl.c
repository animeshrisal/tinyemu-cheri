/*
 * SDL display driver
 *
 * Copyright (c) 2017 Fabrice Bellard
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <inttypes.h>
#include <assert.h>
#include <fcntl.h>
#include <errno.h>

#include <SDL2/SDL.h>

#include "cutils.h"
#include "virtio.h"
#include "machine.h"

#define KEYCODE_MAX 127

static SDL_Window *window;
static SDL_Renderer *renderer;
static SDL_Texture *fb_texture;
static int window_width, window_height, fb_width, fb_height;
static SDL_Cursor *sdl_cursor_hidden;
static uint8_t key_pressed[KEYCODE_MAX + 1];

static void sdl_update_fb_texture(FBDevice *fb_dev)
{
    if (!fb_texture ||
        fb_width != fb_dev->width ||
        fb_height != fb_dev->height) {

        if (fb_texture != NULL)
            SDL_DestroyTexture(fb_texture);

        fb_width = fb_dev->width;
        fb_height = fb_dev->height;

        fb_texture = SDL_CreateTexture(renderer,
                                       SDL_PIXELFORMAT_ARGB8888,
                                       SDL_TEXTUREACCESS_STREAMING,
                                       fb_dev->width,
                                       fb_dev->height);
        if (!fb_texture) {
            fprintf(stderr, "Could not create SDL framebuffer texture\n");
            exit(1);
        }
    }
}

static void sdl_update(FBDevice *fb_dev, void *opaque,
                       int x, int y, int w, int h)
{
    int *dirty = (int *)opaque;
    *dirty = 1;
}

#if defined(_WIN32) || defined(__HAIKU__)

static int sdl_get_keycode(const SDL_KeyboardEvent *ev)
{
    return ev->keysym.scancode;
}

#elif defined(__APPLE__)

static int sdl_get_keycode(const SDL_KeyboardEvent *ev)
{
    // Haiku keycodes according to https://www.haiku-os.org/docs/api/keyboard.html
    fprintf(stderr, "Scancode: %x\n", ev->keysym.scancode);
    switch (ev->keysym.scancode) {
        case SDL_SCANCODE_ESCAPE: return 1;
        case SDL_SCANCODE_1: return 0x12;
        case SDL_SCANCODE_2: return 0x13;
        case SDL_SCANCODE_3: return 0x14;
        case SDL_SCANCODE_4: return 0x15;
        case SDL_SCANCODE_5: return 0x16;
        case SDL_SCANCODE_6: return 0x17;
        case SDL_SCANCODE_7: return 0x18;
        case SDL_SCANCODE_8: return 0x19;
        case SDL_SCANCODE_9: return 0x1a;
        case SDL_SCANCODE_0: return 0x1b;
        case SDL_SCANCODE_MINUS: return 0x1c;
        case SDL_SCANCODE_EQUALS: return 0x1d;
        case SDL_SCANCODE_BACKSPACE: return 0x1e;
        case SDL_SCANCODE_TAB: return 0x26;
        case SDL_SCANCODE_Q: return 0x27;
        case SDL_SCANCODE_W: return 0x28;
        case SDL_SCANCODE_E: return 0x29;
        case SDL_SCANCODE_R: return 0x2a;
        case SDL_SCANCODE_T: return 0x2b;
        case SDL_SCANCODE_Y: return 0x2c;
        case SDL_SCANCODE_U: return 0x2d;
        case SDL_SCANCODE_I: return 0x2e;
        case SDL_SCANCODE_O: return 0x2f;
        case SDL_SCANCODE_P: return 0x30;
        case SDL_SCANCODE_LEFTBRACKET: return 0x31;
        case SDL_SCANCODE_RIGHTBRACKET: return 0x32;
        case SDL_SCANCODE_RETURN: return 0x47;
        case SDL_SCANCODE_LCTRL: return 0x5c;
        case SDL_SCANCODE_A: return 0x3c;
        case SDL_SCANCODE_S: return 0x3d;
        case SDL_SCANCODE_D: return 0x3e;
        case SDL_SCANCODE_F: return 0x3f;
        case SDL_SCANCODE_G: return 0x40;
        case SDL_SCANCODE_H: return 0x41;
        case SDL_SCANCODE_J: return 0x42;
        case SDL_SCANCODE_K: return 0x43;
        case SDL_SCANCODE_L: return 0x44;
        case SDL_SCANCODE_SEMICOLON: return 0x45;
        case SDL_SCANCODE_APOSTROPHE: return 0x46;
        case SDL_SCANCODE_GRAVE: return 0x11;
        case SDL_SCANCODE_LSHIFT: return 0x4b;
        case SDL_SCANCODE_BACKSLASH: return 0x33;
        case SDL_SCANCODE_Z: return 0x4c;
        case SDL_SCANCODE_X: return 0x4d;
        case SDL_SCANCODE_C: return 0x4e;
        case SDL_SCANCODE_V: return 0x4f;
        case SDL_SCANCODE_B: return 0x50;
        case SDL_SCANCODE_N: return 0x51;
        case SDL_SCANCODE_M: return 0x52;
        case SDL_SCANCODE_COMMA: return 0x53;
        case SDL_SCANCODE_PERIOD: return 0x54;
        case SDL_SCANCODE_SLASH: return 0x55;
        case SDL_SCANCODE_RSHIFT: return 0x56;
        case SDL_SCANCODE_KP_MULTIPLY: return 0x24;
        case SDL_SCANCODE_LALT: return 0x56;
        case SDL_SCANCODE_SPACE: return 0x5e;
        case SDL_SCANCODE_CAPSLOCK: return 0x3b;
        case SDL_SCANCODE_F1: return 0x02;
        case SDL_SCANCODE_F2: return 0x03;
        case SDL_SCANCODE_F3: return 0x04;
        case SDL_SCANCODE_F4: return 0x05;
        case SDL_SCANCODE_F5: return 0x06;
        case SDL_SCANCODE_F6: return 0x07;
        case SDL_SCANCODE_F7: return 0x08;
        case SDL_SCANCODE_F8: return 0x09;
        case SDL_SCANCODE_F9: return 0x0a;
        case SDL_SCANCODE_F10: return 0x0b;
        case SDL_SCANCODE_NUMLOCKCLEAR: return 0x22;
        case SDL_SCANCODE_SCROLLLOCK: return 0x0f;
        case SDL_SCANCODE_KP_7: return 0x37;
        case SDL_SCANCODE_KP_8: return 0x38;
        case SDL_SCANCODE_KP_9: return 0x39;
        case SDL_SCANCODE_KP_MINUS: return 0x25;
        case SDL_SCANCODE_KP_4: return 0x48;
        case SDL_SCANCODE_KP_5: return 0x49;
        case SDL_SCANCODE_KP_6: return 0x4a;
        case SDL_SCANCODE_KP_PLUS: return 0x3a;
        case SDL_SCANCODE_KP_1: return 0x58;
        case SDL_SCANCODE_KP_2: return 0x59;
        case SDL_SCANCODE_KP_3: return 0x5a;
        case SDL_SCANCODE_KP_0: return 0x64;
        case SDL_SCANCODE_KP_PERIOD: return 0x65;
        case SDL_SCANCODE_LANG5: return 0;
        case SDL_SCANCODE_NONUSBACKSLASH: return 0;
        case SDL_SCANCODE_F11: return 0x0c;
        case SDL_SCANCODE_F12: return 0x0d;
        case SDL_SCANCODE_INTERNATIONAL1: return 0;
        case SDL_SCANCODE_LANG3: return 0;
        case SDL_SCANCODE_LANG4: return 0;
        case SDL_SCANCODE_INTERNATIONAL4: return 0;
        case SDL_SCANCODE_INTERNATIONAL2: return 0;
        case SDL_SCANCODE_INTERNATIONAL5: return 0;
        case SDL_SCANCODE_KP_ENTER: return 0x5b;
        case SDL_SCANCODE_RCTRL: return 0x60;
        case SDL_SCANCODE_KP_DIVIDE: return 0x23;
        case SDL_SCANCODE_SYSREQ: return 0x10;
        case SDL_SCANCODE_RALT: return 0x5f;
        case SDL_SCANCODE_HOME: return 0x20;
        case SDL_SCANCODE_UP: return 0x57;
        case SDL_SCANCODE_PAGEUP: return 0x21;
        case SDL_SCANCODE_LEFT: return 0x61;
        case SDL_SCANCODE_RIGHT: return 0x63;
        case SDL_SCANCODE_END: return 0x35;
        case SDL_SCANCODE_DOWN: return 0x62;
        case SDL_SCANCODE_PAGEDOWN: return 0x36;
        case SDL_SCANCODE_INSERT: return 0x1f;
        case SDL_SCANCODE_DELETE: return 0x34;
        case SDL_SCANCODE_MUTE: return 0;
        case SDL_SCANCODE_VOLUMEDOWN: return 0;
        case SDL_SCANCODE_VOLUMEUP: return 0;
        case SDL_SCANCODE_POWER: return 0;
        case SDL_SCANCODE_KP_EQUALS: return 0;
        case SDL_SCANCODE_KP_PLUSMINUS: return 0;
        case SDL_SCANCODE_PAUSE: return 0x10;
        case SDL_SCANCODE_KP_COMMA: return 0;
        case SDL_SCANCODE_LANG1: return 0;
        case SDL_SCANCODE_LANG2: return 0;
        case SDL_SCANCODE_INTERNATIONAL3: return 0;
        case SDL_SCANCODE_LGUI: return 0x66;
        case SDL_SCANCODE_RGUI: return 0x67;
        case SDL_SCANCODE_APPLICATION: return 0;
        case SDL_SCANCODE_STOP: return 0;
        case SDL_SCANCODE_AGAIN: return 0;
        case SDL_SCANCODE_UNDO: return 0;
        case SDL_SCANCODE_COPY: return 0;
        case SDL_SCANCODE_PASTE: return 0;
        case SDL_SCANCODE_FIND: return 0;
        case SDL_SCANCODE_CUT: return 0;
        case SDL_SCANCODE_HELP: return 0;
        case SDL_SCANCODE_MENU: return 0x68;
        case SDL_SCANCODE_CALCULATOR: return 0;
        case SDL_SCANCODE_SLEEP: return 0;
        case SDL_SCANCODE_APP1: return 0;
        case SDL_SCANCODE_APP2: return 0;
        case SDL_SCANCODE_WWW: return 0;
        case SDL_SCANCODE_MAIL: return 0;
        case SDL_SCANCODE_AC_BOOKMARKS: return 0;
        case SDL_SCANCODE_COMPUTER: return 0;
        case SDL_SCANCODE_AC_BACK: return 0;
        case SDL_SCANCODE_AC_FORWARD: return 0;
        case SDL_SCANCODE_EJECT: return 0;
        case SDL_SCANCODE_AUDIONEXT: return 0;
        case SDL_SCANCODE_AUDIOPLAY: return 0;
        case SDL_SCANCODE_AUDIOPREV: return 0;
        case SDL_SCANCODE_AUDIOSTOP: return 0;
#if SDL_VERSION_ATLEAST(2, 0, 6)
        case SDL_SCANCODE_AUDIOREWIND: return 0;
#endif
        case SDL_SCANCODE_AC_HOME: return 0;
        case SDL_SCANCODE_AC_REFRESH: return 0;
        case SDL_SCANCODE_KP_LEFTPAREN: return 0;
        case SDL_SCANCODE_KP_RIGHTPAREN: return 0;
        case SDL_SCANCODE_F13: return 0;
        case SDL_SCANCODE_F14: return 0;
        case SDL_SCANCODE_F15: return 0;
        case SDL_SCANCODE_F16: return 0;
        case SDL_SCANCODE_F17: return 0;
        case SDL_SCANCODE_F18: return 0;
        case SDL_SCANCODE_F19: return 0;
        case SDL_SCANCODE_F20: return 0;
        case SDL_SCANCODE_F21: return 0;
        case SDL_SCANCODE_F22: return 0;
        case SDL_SCANCODE_F23: return 0;
        case SDL_SCANCODE_F24: return 0;
#if SDL_VERSION_ATLEAST(2, 0, 6)
        case SDL_SCANCODE_AUDIOFASTFORWARD: return 0;
#endif
        case SDL_SCANCODE_AC_SEARCH: return 0;
        case SDL_SCANCODE_ALTERASE: return 0;
        case SDL_SCANCODE_CANCEL: return 0;
        case SDL_SCANCODE_BRIGHTNESSDOWN: return 0;
        case SDL_SCANCODE_BRIGHTNESSUP: return 0;
        case SDL_SCANCODE_DISPLAYSWITCH: return 0;
        case SDL_SCANCODE_KBDILLUMTOGGLE: return 0;
        case SDL_SCANCODE_KBDILLUMDOWN: return 0;
        case SDL_SCANCODE_KBDILLUMUP: return 0;
        default: return 0;
    }
}
#else
/* we assume Xorg is used with a PC keyboard. Return 0 if no keycode found. */
static int sdl_get_keycode(const SDL_KeyboardEvent *ev)
{
    int keycode;
    keycode = ev->keysym.scancode;
    if (keycode < 9) {
        keycode = 0;
    } else if (keycode < 127 + 8) {
        keycode -= 8;
    } else {
        keycode = 0;
    }
    return keycode;
}

#endif

/* release all pressed keys */
static void sdl_reset_keys(VirtMachine *m)
{
    int i;

    for(i = 1; i <= KEYCODE_MAX; i++) {
        if (key_pressed[i]) {
            vm_send_key_event(m, FALSE, i);
            key_pressed[i] = FALSE;
        }
    }
}

static void sdl_handle_key_event(const SDL_KeyboardEvent *ev, VirtMachine *m)
{
    int keycode, keypress;

    keycode = sdl_get_keycode(ev);
    if (keycode) {
        if (keycode == 0x3a || keycode ==0x45) {
            /* SDL does not generate key up for numlock & caps lock */
            vm_send_key_event(m, TRUE, keycode);
            vm_send_key_event(m, FALSE, keycode);
        } else {
            keypress = (ev->type == SDL_KEYDOWN);
            if (keycode <= KEYCODE_MAX)
                key_pressed[keycode] = keypress;
            vm_send_key_event(m, keypress, keycode);
        }
    } else if (ev->type == SDL_KEYUP) {
        /* workaround to reset the keyboard state (used when changing
           desktop with ctrl-alt-x on Linux) */
        sdl_reset_keys(m);
    }
}

static void sdl_send_mouse_event(VirtMachine *m, int x1, int y1,
                                 int dz, int state, BOOL is_absolute)
{
    int buttons, x, y;

    buttons = 0;
    if (state & SDL_BUTTON(SDL_BUTTON_LEFT))
        buttons |= (1 << 0);
    if (state & SDL_BUTTON(SDL_BUTTON_RIGHT))
        buttons |= (1 << 1);
    if (state & SDL_BUTTON(SDL_BUTTON_MIDDLE))
        buttons |= (1 << 2);
    if (is_absolute) {
        x = (x1 * 32768) / window_width;
        y = (y1 * 32768) / window_height;
    } else {
        x = x1;
        y = y1;
    }
    vm_send_mouse_event(m, x, y, dz, buttons);
}

static void sdl_handle_mouse_motion_event(const SDL_Event *ev, VirtMachine *m)
{
    BOOL is_absolute = vm_mouse_is_absolute(m);
    int x, y;
    if (is_absolute) {
        x = ev->motion.x;
        y = ev->motion.y;
    } else {
        x = ev->motion.xrel;
        y = ev->motion.yrel;
    }
    sdl_send_mouse_event(m, x, y, 0, ev->motion.state, is_absolute);
}

static void sdl_handle_mouse_button_event(const SDL_Event *ev, VirtMachine *m)
{
    BOOL is_absolute = vm_mouse_is_absolute(m);
    int state, dz;

    dz = 0;
    if (ev->type == SDL_MOUSEWHEEL)
        dz = ev->wheel.y;

    state = SDL_GetMouseState(NULL, NULL);
    /* just in case */
    if (ev->type == SDL_MOUSEBUTTONDOWN)
        state |= SDL_BUTTON(ev->button.button);
    else
        state &= ~SDL_BUTTON(ev->button.button);

    if (is_absolute) {
        sdl_send_mouse_event(m, ev->button.x, ev->button.y,
                             dz, state, is_absolute);
    } else {
        sdl_send_mouse_event(m, 0, 0, dz, state, is_absolute);
    }
}

void sdl_refresh(VirtMachine *m)
{
    SDL_Event ev_s, *ev = &ev_s;

    if (!m->fb_dev)
        return;

    sdl_update_fb_texture(m->fb_dev);

    int dirty = 0;
    m->fb_dev->refresh(m->fb_dev, sdl_update, &dirty);

    if (dirty) {
        SDL_UpdateTexture(fb_texture, NULL,
                          m->fb_dev->fb_data,
                          m->fb_dev->stride);
        SDL_RenderClear(renderer);
        SDL_RenderCopy(renderer, fb_texture, NULL, NULL);
        SDL_RenderPresent(renderer);
    }

    while (SDL_PollEvent(ev)) {
        switch (ev->type) {
        case SDL_KEYDOWN:
        case SDL_KEYUP:
            sdl_handle_key_event(&ev->key, m);
            break;
        case SDL_MOUSEMOTION:
            sdl_handle_mouse_motion_event(ev, m);
            break;
        case SDL_MOUSEBUTTONDOWN:
        case SDL_MOUSEBUTTONUP:
            sdl_handle_mouse_button_event(ev, m);
            break;
        case SDL_QUIT:
            exit(0);
        }
    }
}

static void sdl_hide_cursor(void)
{
    uint8_t data = 0;
    sdl_cursor_hidden = SDL_CreateCursor(&data, &data, 8, 1, 0, 0);
    SDL_ShowCursor(1);
    SDL_SetCursor(sdl_cursor_hidden);
}

void sdl_init(int width, int height)
{
    window_width = width;
    window_height = height;

    if (SDL_Init(SDL_INIT_VIDEO | SDL_INIT_NOPARACHUTE)) {
        fprintf(stderr, "Could not initialize SDL - exiting\n");
        exit(1);
    }

    int result = SDL_CreateWindowAndRenderer(width, height, 0, &window, &renderer);
    if (result == -1) {
        fprintf(stderr, "Could not create SDL window\n");
        exit(1);
    }

    SDL_SetWindowTitle(window, "TinyEMU");

    sdl_hide_cursor();
}
