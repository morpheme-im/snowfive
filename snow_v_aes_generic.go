package snowfive

import "math/bits"

func aesRoundPairGeneric(dstR2, dstR3, srcR1, srcR2 *[4]uint32) {
	q := [8]uint32{
		srcR1[0], srcR2[0], srcR1[1], srcR2[1],
		srcR1[2], srcR2[2], srcR1[3], srcR2[3],
	}
	orthogonalize(&q)
	bitsliceSBox(&q)
	orthogonalize(&q)

	a0, a1, a2, a3 := q[0], q[2], q[4], q[6]
	b0, b1, b2, b3 := q[1], q[3], q[5], q[7]
	dstR2[0] = mixColumn((a0 & 0x000000ff) | (a1 & 0x0000ff00) | (a2 & 0x00ff0000) | (a3 & 0xff000000))
	dstR2[1] = mixColumn((a1 & 0x000000ff) | (a2 & 0x0000ff00) | (a3 & 0x00ff0000) | (a0 & 0xff000000))
	dstR2[2] = mixColumn((a2 & 0x000000ff) | (a3 & 0x0000ff00) | (a0 & 0x00ff0000) | (a1 & 0xff000000))
	dstR2[3] = mixColumn((a3 & 0x000000ff) | (a0 & 0x0000ff00) | (a1 & 0x00ff0000) | (a2 & 0xff000000))
	dstR3[0] = mixColumn((b0 & 0x000000ff) | (b1 & 0x0000ff00) | (b2 & 0x00ff0000) | (b3 & 0xff000000))
	dstR3[1] = mixColumn((b1 & 0x000000ff) | (b2 & 0x0000ff00) | (b3 & 0x00ff0000) | (b0 & 0xff000000))
	dstR3[2] = mixColumn((b2 & 0x000000ff) | (b3 & 0x0000ff00) | (b0 & 0x00ff0000) | (b1 & 0xff000000))
	dstR3[3] = mixColumn((b3 & 0x000000ff) | (b0 & 0x0000ff00) | (b1 & 0x00ff0000) | (b2 & 0xff000000))
}

func orthogonalize(q *[8]uint32) {
	x := q[0]
	q[0] = (x & 0x55555555) | ((q[1] & 0x55555555) << 1)
	q[1] = ((x & 0xaaaaaaaa) >> 1) | (q[1] & 0xaaaaaaaa)
	x = q[2]
	q[2] = (x & 0x55555555) | ((q[3] & 0x55555555) << 1)
	q[3] = ((x & 0xaaaaaaaa) >> 1) | (q[3] & 0xaaaaaaaa)
	x = q[4]
	q[4] = (x & 0x55555555) | ((q[5] & 0x55555555) << 1)
	q[5] = ((x & 0xaaaaaaaa) >> 1) | (q[5] & 0xaaaaaaaa)
	x = q[6]
	q[6] = (x & 0x55555555) | ((q[7] & 0x55555555) << 1)
	q[7] = ((x & 0xaaaaaaaa) >> 1) | (q[7] & 0xaaaaaaaa)

	x = q[0]
	q[0] = (x & 0x33333333) | ((q[2] & 0x33333333) << 2)
	q[2] = ((x & 0xcccccccc) >> 2) | (q[2] & 0xcccccccc)
	x = q[1]
	q[1] = (x & 0x33333333) | ((q[3] & 0x33333333) << 2)
	q[3] = ((x & 0xcccccccc) >> 2) | (q[3] & 0xcccccccc)
	x = q[4]
	q[4] = (x & 0x33333333) | ((q[6] & 0x33333333) << 2)
	q[6] = ((x & 0xcccccccc) >> 2) | (q[6] & 0xcccccccc)
	x = q[5]
	q[5] = (x & 0x33333333) | ((q[7] & 0x33333333) << 2)
	q[7] = ((x & 0xcccccccc) >> 2) | (q[7] & 0xcccccccc)

	x = q[0]
	q[0] = (x & 0x0f0f0f0f) | ((q[4] & 0x0f0f0f0f) << 4)
	q[4] = ((x & 0xf0f0f0f0) >> 4) | (q[4] & 0xf0f0f0f0)
	x = q[1]
	q[1] = (x & 0x0f0f0f0f) | ((q[5] & 0x0f0f0f0f) << 4)
	q[5] = ((x & 0xf0f0f0f0) >> 4) | (q[5] & 0xf0f0f0f0)
	x = q[2]
	q[2] = (x & 0x0f0f0f0f) | ((q[6] & 0x0f0f0f0f) << 4)
	q[6] = ((x & 0xf0f0f0f0) >> 4) | (q[6] & 0xf0f0f0f0)
	x = q[3]
	q[3] = (x & 0x0f0f0f0f) | ((q[7] & 0x0f0f0f0f) << 4)
	q[7] = ((x & 0xf0f0f0f0) >> 4) | (q[7] & 0xf0f0f0f0)
}

func bitsliceSBox(q *[8]uint32) {
	x0, x1, x2, x3 := q[7], q[6], q[5], q[4]
	x4, x5, x6, x7 := q[3], q[2], q[1], q[0]
	y14 := x3 ^ x5
	y13 := x0 ^ x6
	y9 := x0 ^ x3
	y8 := x0 ^ x5
	t0 := x1 ^ x2
	y1 := t0 ^ x7
	y4 := y1 ^ x3
	y12 := y13 ^ y14
	y2 := y1 ^ x0
	y5 := y1 ^ x6
	y3 := y5 ^ y8
	t1 := x4 ^ y12
	y15 := t1 ^ x5
	y20 := t1 ^ x1
	y6 := y15 ^ x7
	y10 := y15 ^ t0
	y11 := y20 ^ y9
	y7 := x7 ^ y11
	y17 := y10 ^ y11
	y19 := y10 ^ y8
	y16 := t0 ^ y11
	y21 := y13 ^ y16
	y18 := x0 ^ y16
	t2 := y12 & y15
	t3 := y3 & y6
	t4 := t3 ^ t2
	t5 := y4 & x7
	t6 := t5 ^ t2
	t7 := y13 & y16
	t8 := y5 & y1
	t9 := t8 ^ t7
	t10 := y2 & y7
	t11 := t10 ^ t7
	t12 := y9 & y11
	t13 := y14 & y17
	t14 := t13 ^ t12
	t15 := y8 & y10
	t16 := t15 ^ t12
	t17 := t4 ^ t14
	t18 := t6 ^ t16
	t19 := t9 ^ t14
	t20 := t11 ^ t16
	t21 := t17 ^ y20
	t22 := t18 ^ y19
	t23 := t19 ^ y21
	t24 := t20 ^ y18
	t25 := t21 ^ t22
	t26 := t21 & t23
	t27 := t24 ^ t26
	t28 := t25 & t27
	t29 := t28 ^ t22
	t30 := t23 ^ t24
	t31 := t22 ^ t26
	t32 := t31 & t30
	t33 := t32 ^ t24
	t34 := t23 ^ t33
	t35 := t27 ^ t33
	t36 := t24 & t35
	t37 := t36 ^ t34
	t38 := t27 ^ t36
	t39 := t29 & t38
	t40 := t25 ^ t39
	t41 := t40 ^ t37
	t42 := t29 ^ t33
	t43 := t29 ^ t40
	t44 := t33 ^ t37
	t45 := t42 ^ t41
	z0 := t44 & y15
	z1 := t37 & y6
	z2 := t33 & x7
	z3 := t43 & y16
	z4 := t40 & y1
	z5 := t29 & y7
	z6 := t42 & y11
	z7 := t45 & y17
	z8 := t41 & y10
	z9 := t44 & y12
	z10 := t37 & y3
	z11 := t33 & y4
	z12 := t43 & y13
	z13 := t40 & y5
	z14 := t29 & y2
	z15 := t42 & y9
	z16 := t45 & y14
	z17 := t41 & y8
	t46 := z15 ^ z16
	t47 := z10 ^ z11
	t48 := z5 ^ z13
	t49 := z9 ^ z10
	t50 := z2 ^ z12
	t51 := z2 ^ z5
	t52 := z7 ^ z8
	t53 := z0 ^ z3
	t54 := z6 ^ z7
	t55 := z16 ^ z17
	t56 := z12 ^ t48
	t57 := t50 ^ t53
	t58 := z4 ^ t46
	t59 := z3 ^ t54
	t60 := t46 ^ t57
	t61 := z14 ^ t57
	t62 := t52 ^ t58
	t63 := t49 ^ t58
	t64 := z4 ^ t59
	t65 := t61 ^ t62
	t66 := z1 ^ t63
	s0 := t59 ^ t63
	s6 := t56 ^ ^t62
	s7 := t48 ^ ^t60
	t67 := t64 ^ t65
	s3 := t53 ^ t66
	s4 := t51 ^ t66
	s5 := t47 ^ t65
	s1 := t64 ^ ^s3
	s2 := t55 ^ ^t67
	q[7], q[6], q[5], q[4] = s0, s1, s2, s3
	q[3], q[2], q[1], q[0] = s4, s5, s6, s7
}

func mixColumn(x uint32) uint32 {
	r8 := bits.RotateLeft32(x, -8)
	t := x ^ r8 ^ bits.RotateLeft32(x, -16) ^ bits.RotateLeft32(x, -24)
	return x ^ t ^ xtimeBytes(x^r8)
}

func xtimeBytes(v uint32) uint32 {
	return ((v << 1) & 0xfefefefe) ^ (((v >> 7) & 0x01010101) * 0x1b)
}
