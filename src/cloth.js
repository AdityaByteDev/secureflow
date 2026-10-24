/* Cloth physics for the hero cover. Baked once (in a Web Worker) into frames the 3D stage replays on scroll. */
function bakeCloth(c){
  var NX=c.nx, NZ=c.nz, N=NX*NZ, W=c.width, L=c.length, dt=1/c.hz, G=-9.8*dt*dt, IT=c.iters;
  var P=new Float32Array(N*3), Q=new Float32Array(N*3), inv=new Float32Array(N), hit=new Uint8Array(N);
  var seed=11; function rnd(){ seed=(seed*16807)%2147483647; return seed/2147483647; }
  var i,j,k,s;
  for (j=0;j<NZ;j++) for (i=0;i<NX;i++){
    k=j*NX+i; var z=(j/(NZ-1)-.5)*L;
    P[k*3]=(i/(NX-1)-.5)*W; P[k*3+1]=c.top+c.round+0.03+Math.abs(z)*0.02+rnd()*0.004; P[k*3+2]=z;
    inv[k]=1;
  }
  Q.set(P);
  var A=[],B=[],R=[],S=[];
  function add(a,b,st){ var dx=P[a*3]-P[b*3], dy=P[a*3+1]-P[b*3+1], dz=P[a*3+2]-P[b*3+2]; A.push(a); B.push(b); R.push(Math.sqrt(dx*dx+dy*dy+dz*dz)); S.push(st); }
  for (j=0;j<NZ;j++) for (i=0;i<NX;i++){
    k=j*NX+i;
    if (i<NX-1) add(k,k+1,1);
    if (j<NZ-1) add(k,k+NX,1);
    if (i<NX-1&&j<NZ-1){ add(k,k+NX+1,.7); add(k+1,k+NX,.7); }
    if (i<NX-2) add(k,k+2,c.bend);
    if (j<NZ-2) add(k,k+2*NX,c.bend);
  }
  var CA=new Int32Array(A), CB=new Int32Array(B), CR=new Float32Array(R), CS=new Float32Array(S), NC=CA.length;
  // collide against a ROUNDED shell around the slab, so straight cloth triangles never cut its sharp corners
  var th=c.thick, RR=c.round, bx=c.box[0], by=c.box[1], bz=c.box[2], hx=c.box[3], hy=c.box[4], hz=c.box[5], pr2=c.plinthR*c.plinthR, pt=c.plinthTop+th;
  function sg(v){ return v<0?-1:1; }
  function collide(){
    for (var k=0;k<N;k++){
      var o=k*3, x=P[o], y=P[o+1], z=P[o+2], dx=x-bx, dy=y-by, dz=z-bz;
      var qx=Math.abs(dx)-hx, qy=Math.abs(dy)-hy, qz=Math.abs(dz)-hz, mx=qx>0?qx:0, my=qy>0?qy:0, mz=qz>0?qz:0;
      var outer=Math.sqrt(mx*mx+my*my+mz*mz), inner=Math.min(Math.max(qx,qy,qz),0), d=outer+inner-RR;
      if (d<0){
        var nx=0, ny=0, nz=0;
        if (outer>1e-6){ nx=mx/outer*sg(dx); ny=my/outer*sg(dy); nz=mz/outer*sg(dz); }
        else if (qx>=qy && qx>=qz) nx=sg(dx); else if (qy>=qz) ny=sg(dy); else nz=sg(dz);
        x-=nx*d; y-=ny*d; z-=nz*d; hit[k]=1;
      }
      if (x*x+z*z<pr2){ if (y<pt){ y=pt; hit[k]=1; } } else if (y<th){ y=th; hit[k]=1; }
      P[o]=x; P[o+1]=y; P[o+2]=z;
    }
  }
  function step(damp, fric){
    for (var k=0;k<N;k++){
      if (!inv[k]) continue;
      var o=k*3;
      for (var a=0;a<3;a++){ var p=P[o+a], v=(p-Q[o+a])*damp; Q[o+a]=p; P[o+a]=p+v; }
      P[o+1]+=G;
    }
    for (var it=0;it<IT;it++){
      for (var n=0;n<NC;n++){
        var a1=CA[n], b1=CB[n], wa=inv[a1], wb=inv[b1], ws=wa+wb; if (!ws) continue;
        var oa=a1*3, ob=b1*3, dx=P[ob]-P[oa], dy=P[ob+1]-P[oa+1], dz=P[ob+2]-P[oa+2], d=Math.sqrt(dx*dx+dy*dy+dz*dz);
        if (d<1e-9) continue;
        var f=(d-CR[n])/d*CS[n]/ws;
        P[oa]+=dx*f*wa; P[oa+1]+=dy*f*wa; P[oa+2]+=dz*f*wa;
        P[ob]-=dx*f*wb; P[ob+1]-=dy*f*wb; P[ob+2]-=dz*f*wb;
      }
      collide();
    }
    for (k=0;k<N;k++) if (hit[k]){ var o2=k*3; for (var a2=0;a2<3;a2++) Q[o2+a2]=P[o2+a2]-(P[o2+a2]-Q[o2+a2])*(1-fric); hit[k]=0; }
  }
  var settle=Math.round(c.settle*c.hz);
  for (s=0;s<settle;s++) step(s<settle*.6?0.95:0.985, .7);
  Q.set(P);
  var grab=[], S0=new Float32Array(P);
  for (j=0;j<c.grabRows;j++) for (i=0;i<NX;i++){ k=j*NX+i; grab.push(k); inv[k]=0; }
  var pullSteps=Math.round(c.pull*c.hz), total=pullSteps+Math.round(c.tail*c.hz), every=c.every;
  var F=1+Math.floor(total/every), frames=new Float32Array(F*N*3), fi=1;
  frames.set(P,0);
  for (s=1;s<=total;s++){
    var e=Math.pow(s/pullSteps,1.7);
    for (var g=0;g<grab.length;g++){
      var kk=grab[g], side=(kk%NX)/(NX-1), oo=kk*3;
      Q[oo]=P[oo]; Q[oo+1]=P[oo+1]; Q[oo+2]=P[oo+2];
      P[oo]  =S0[oo]  + e*(c.pdx + (side-.5)*c.spread*e);
      P[oo+1]=S0[oo+1]+ e*c.pdy*(0.75+0.5*side);
      P[oo+2]=S0[oo+2]+ e*c.pdz;
    }
    step(0.99, .35);
    if (s%every===0 && fi<F){ frames.set(P, fi*N*3); fi++; }
  }
  return { frames:frames, F:fi, NX:NX, NZ:NZ };
}
