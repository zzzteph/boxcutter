// PS1-style screen pass: the game world is rendered at low resolution, then
// shown with nearest-neighbour scaling, cut down to 15-bit colour (5 bits per
// channel) with a 4x4 ordered (Bayer) dither, like the console's GPU did.
shader_type canvas_item;

uniform float levels = 31.0;
uniform float dither = 1.0;

const float BAYER[16] = float[16](
	0.0, 8.0, 2.0, 10.0,
	12.0, 4.0, 14.0, 6.0,
	3.0, 11.0, 1.0, 9.0,
	15.0, 7.0, 13.0, 5.0);

void fragment() {
	vec4 c = texture(TEXTURE, UV);
	ivec2 p = ivec2(UV * vec2(textureSize(TEXTURE, 0)));
	float b = (BAYER[(p.y % 4) * 4 + (p.x % 4)] + 0.5) / 16.0 - 0.5;
	vec3 q = floor(c.rgb * levels + 0.5 + b * dither) / levels;
	COLOR = vec4(clamp(q, 0.0, 1.0), 1.0);
}
