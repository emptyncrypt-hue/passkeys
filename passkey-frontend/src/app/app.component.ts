import { Component } from '@angular/core';
import { HttpClient, HttpClientModule } from '@angular/common/http';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { fido2Create, fido2Get } from '@ownid/webauthn';

interface OperationResult { res?: boolean; authenticated?: boolean; username?: string; }

@Component({
  selector: 'app-root',
  standalone: true,
  imports: [FormsModule, CommonModule, HttpClientModule],
  template: `
    <main>
      <h1>Passkeys Demo</h1>
      <label for="username">Username</label>
      <input id="username" [(ngModel)]="username" autocomplete="username" maxlength="64" />
      <button [disabled]="busy" (click)="registerStart()">Register</button>
      <button [disabled]="busy" (click)="loginStart()">Login</button>
      <button [disabled]="busy" (click)="logout()">Log out</button>
      <p role="status">{{ status }}</p>
    </main>
  `,
})
export class AppComponent {
  username = '';
  status = 'Not authenticated';
  busy = false;
  constructor(private http: HttpClient) {}

  async registerStart() {
    if (this.busy) return;
    this.busy = true;
    try {
      const options = await this.http.post('/register/start', { username: this.username }).toPromise();
      const response: any = await fido2Create(options, this.username);
      const result = await this.http.post<OperationResult>('/register/finish', {
        username: this.username, data: response?.data ?? response,
      }).toPromise();
      this.status = result?.res ? 'Registration complete. Please log in.' : 'Registration failed';
    } catch (error) {
      this.status = 'Registration failed or was cancelled';
    } finally {
      this.busy = false;
    }
  }

  async loginStart() {
    if (this.busy) return;
    this.busy = true;
    try {
      const options = await this.http.post('/login/start', { username: this.username }).toPromise();
      const response: any = await fido2Get(options as PublicKeyCredentialRequestOptions, this.username);
      const result = await this.http.post<OperationResult>('/login/finish', {
        username: this.username, data: response?.data ?? response,
      }).toPromise();
      this.status = result?.res ? 'Authenticated' : 'Authentication failed';
    } catch (error) {
      this.status = 'Authentication failed or was cancelled';
    } finally {
      this.busy = false;
    }
  }

  async logout() {
    if (this.busy) return;
    this.busy = true;
    try {
      await this.http.post('/logout', {}).toPromise();
      this.status = 'Logged out';
    } catch (error) {
      this.status = 'Logout failed';
    } finally {
      this.busy = false;
    }
  }
}
